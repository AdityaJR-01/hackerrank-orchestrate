import copy
import hashlib
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Generic, List, Optional, Sequence, Tuple, Type, TypeVar

from pydantic import BaseModel, ValidationError
from llm_harness import AllRoutesExhausted, CallRecord, OrchestrateLLM

S = TypeVar("S")
R = TypeVar("R")
T = TypeVar("T", bound=BaseModel)


class OriginResetError(Exception):
    """
    Raised when every route rejects grounding against upstream state (or a final
    continuity invariant fails), requiring the work unit's checkpoint lineage to be
    wiped and re-executed cleanly from Step 0.
    """
    pass


class UniversalCheckpointJournal:
    def __init__(self, db_path: str = "cache/tx_journal.sqlite"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS step_lineage (
                    lineage_key TEXT PRIMARY KEY,
                    work_id TEXT,
                    step_index INTEGER,
                    step_id TEXT,
                    parent_state_hash TEXT,
                    output_json TEXT,
                    post_state_hash TEXT,
                    provider TEXT,
                    model TEXT,
                    telemetry_json TEXT,
                    created_at TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_lineage_work ON step_lineage(work_id);")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sealed_units (
                    work_id TEXT PRIMARY KEY,
                    pipeline_version TEXT,
                    input_fingerprint TEXT,
                    result_json TEXT,
                    telemetry_json TEXT,
                    sealed_at TEXT
                )
                """
            )

    @staticmethod
    def fingerprint_any(obj: Any) -> str:
        if isinstance(obj, BaseModel):
            raw = obj.model_dump_json()
        elif isinstance(obj, (bytes, bytearray)):
            return hashlib.sha256(obj).hexdigest()
        else:
            raw = json.dumps(
                obj,
                sort_keys=True,
                ensure_ascii=True,
                default=lambda o: sorted(o) if isinstance(o, (set, frozenset)) else str(o),
            )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_step_checkpoint(self, lineage_key: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM step_lineage WHERE lineage_key = ?", (lineage_key,)
            ).fetchone()
            return dict(row) if row else None

    def save_step_checkpoint(
        self,
        *,
        lineage_key: str,
        work_id: str,
        step_index: int,
        step_id: str,
        parent_state_hash: str,
        output_json: str,
        post_state_hash: str,
        provider: str,
        model: str,
        telemetry_dict: Dict[str, Any],
    ) -> None:
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO step_lineage (
                    lineage_key, work_id, step_index, step_id, parent_state_hash,
                    output_json, post_state_hash, provider, model, telemetry_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lineage_key,
                    work_id,
                    step_index,
                    step_id,
                    parent_state_hash,
                    output_json,
                    post_state_hash,
                    provider,
                    model,
                    json.dumps(telemetry_dict),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def purge_from_step(self, work_id: str, from_step_index: int = 0) -> None:
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute(
                "DELETE FROM step_lineage WHERE work_id = ? AND step_index >= ?",
                (work_id, from_step_index),
            )
            conn.execute("DELETE FROM sealed_units WHERE work_id = ?", (work_id,))

    def get_sealed_unit(
        self, work_id: str, pipeline_version: str, input_fingerprint: str
    ) -> Optional[Tuple[Any, List[Dict[str, Any]]]]:
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT result_json, telemetry_json FROM sealed_units
                WHERE work_id = ? AND pipeline_version = ? AND input_fingerprint = ?
                """,
                (work_id, pipeline_version, input_fingerprint),
            ).fetchone()
            if not row:
                return None
            return json.loads(row["result_json"]), json.loads(row["telemetry_json"])

    def seal_unit(
        self,
        *,
        work_id: str,
        pipeline_version: str,
        input_fingerprint: str,
        result_obj: Any,
        telemetry_list: List[Dict[str, Any]],
    ) -> None:
        res_json = (
            result_obj.model_dump_json()
            if isinstance(result_obj, BaseModel)
            else json.dumps(
                result_obj,
                sort_keys=True,
                default=lambda o: sorted(o) if isinstance(o, (set, frozenset)) else str(o),
            )
        )
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sealed_units (
                    work_id, pipeline_version, input_fingerprint, result_json, telemetry_json, sealed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    work_id,
                    pipeline_version,
                    input_fingerprint,
                    res_json,
                    json.dumps(telemetry_list),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


class TxContext(Generic[S]):
    def __init__(
        self,
        work_id: str,
        initial_state: S,
        llm: OrchestrateLLM,
        journal: UniversalCheckpointJournal,
    ):
        self.work_id = work_id
        self._origin_state: S = copy.deepcopy(initial_state)
        self.state: S = copy.deepcopy(initial_state)
        self.llm = llm
        self.journal = journal
        self.step_counter: int = 0
        self.unit_telemetry: List[CallRecord] = []
        self._savepoints: Dict[str, Tuple[int, S]] = {}

    def savepoint(self, name: str) -> None:
        self._savepoints[name] = (self.step_counter, copy.deepcopy(self.state))

    def rollback_to_savepoint(self, name: str) -> None:
        if name not in self._savepoints:
            raise OriginResetError(f"Savepoint '{name}' not found; escalating to full origin reset.")
        saved_idx, saved_state = self._savepoints[name]
        self.journal.purge_from_step(self.work_id, from_step_index=saved_idx)
        self.state = copy.deepcopy(saved_state)
        self.step_counter = saved_idx
        self.unit_telemetry = self.unit_telemetry[:saved_idx]

    async def step(
        self,
        *,
        step_id: str,
        system_prompt: str,
        user_prompt: str,
        schema_cls: Type[T],
        reducer_fn: Optional[Callable[[S, T], S]] = None,
        grounding_guard_fn: Optional[Callable[[S, T], bool]] = None,
        media_paths: Optional[Sequence[str | Path]] = None,
    ) -> T:
        idx = self.step_counter
        parent_hash = self.journal.fingerprint_any(self.state)

        lineage_payload = {
            "work_id": self.work_id,
            "step_index": idx,
            "step_id": step_id,
            "parent_state_hash": parent_hash,
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "schema": schema_cls.model_json_schema(),
            "media": [str(p) for p in (media_paths or [])],
        }
        lineage_key = self.journal.fingerprint_any(lineage_payload)

        # 1. Check Lineage Cache (Resumes in 0ms if this step + parent state succeeded before)
        cached_step = self.journal.get_step_checkpoint(lineage_key)
        if cached_step is not None:
            try:
                parsed = schema_cls.model_validate_json(cached_step["output_json"])
                if grounding_guard_fn is None or grounding_guard_fn(self.state, parsed):
                    if reducer_fn is not None:
                        self.state = reducer_fn(self.state, parsed)
                    rec_dict = json.loads(cached_step["telemetry_json"])
                    rec_dict["cached"] = True
                    rec = CallRecord(**rec_dict)
                    self.unit_telemetry.append(rec)
                    self.llm.telemetry.record(rec)
                    self.step_counter += 1
                    return parsed
            except ValidationError:
                pass

        # 2. Live Execution: Validator runs INSIDE the Revolving Door per route
        validator = (lambda out: grounding_guard_fn(self.state, out)) if grounding_guard_fn else None
        try:
            parsed = await self.llm.call_structured(
                request_id=self.work_id,
                task_name=step_id,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                schema_cls=schema_cls,
                image_paths=media_paths,
                use_cache=False,
                validator=validator,
                fallback_factory=None,
            )
        except AllRoutesExhausted as err:
            if err.grounding_rejections > 0:
                raise OriginResetError(
                    f"Step '{step_id}' rejected by {err.grounding_rejections} route(s); resetting unit to origin."
                ) from err
            raise

        if reducer_fn is not None:
            self.state = reducer_fn(self.state, parsed)

        post_hash = self.journal.fingerprint_any(self.state)
        latest_rec = next(
            (
                r
                for r in reversed(self.llm.telemetry.records)
                if r.request_id == self.work_id and r.task_name == step_id and not r.cached
            ),
            CallRecord(self.work_id, "unknown", "unknown", step_id, 0, 0, 0, 0.0, False),
        )
        self.unit_telemetry.append(latest_rec)

        self.journal.save_step_checkpoint(
            lineage_key=lineage_key,
            work_id=self.work_id,
            step_index=idx,
            step_id=step_id,
            parent_state_hash=parent_hash,
            output_json=parsed.model_dump_json(),
            post_state_hash=post_hash,
            provider=latest_rec.provider,
            model=latest_rec.model,
            telemetry_dict=asdict(latest_rec),
        )
        self.step_counter += 1
        return parsed


async def run_work_unit(
    *,
    work_id: str,
    initial_state: S,
    workflow_fn: Callable[[TxContext[S]], Awaitable[R]],
    llm: OrchestrateLLM,
    journal: UniversalCheckpointJournal,
    pipeline_version: str = "v1",
    final_continuity_check: Optional[Callable[[S, R], bool]] = None,
    fallback_result_fn: Optional[Callable[[str, S], R]] = None,
) -> R:
    input_fp = journal.fingerprint_any(initial_state)

    sealed = journal.get_sealed_unit(work_id, pipeline_version, input_fp)
    if sealed is not None:
        result_obj, saved_telemetry = sealed
        for rec_dict in saved_telemetry:
            llm.telemetry.record(CallRecord(**{**rec_dict, "cached": True}))
        return result_obj

    for attempt in (1, 2):
        ctx = TxContext(work_id=work_id, initial_state=initial_state, llm=llm, journal=journal)
        try:
            result = await workflow_fn(ctx)

            if final_continuity_check is not None and not final_continuity_check(ctx.state, result):
                raise OriginResetError(f"Final continuity invariant failed for unit '{work_id}'.")

            journal.seal_unit(
                work_id=work_id,
                pipeline_version=pipeline_version,
                input_fingerprint=input_fp,
                result_obj=result,
                telemetry_list=[asdict(r) for r in ctx.unit_telemetry],
            )
            return result

        except AllRoutesExhausted:
            print(
                f"  [PAUSED] Unit '{work_id}' hit quota exhaustion; "
                f"completed step checkpoints preserved so next run resumes at failed step."
            )
            if fallback_result_fn is not None:
                return fallback_result_fn(work_id, copy.deepcopy(initial_state))
            raise

        except OriginResetError as err:
            if attempt == 1:
                print(
                    f"  [ORIGIN-ROLLBACK] Unit '{work_id}' continuity failed ({err}). "
                    f"Purging step lineage, reverting state to S_0, and retrying cleanly..."
                )
                llm.telemetry.row_rollbacks += 1
                journal.purge_from_step(work_id, from_step_index=0)
                llm.telemetry.purge_request_records(work_id)
                continue
            else:
                print(f"  [SAFE-FALLBACK] Unit '{work_id}' failed after clean rollback. Using deterministic fallback.")
                if fallback_result_fn is not None:
                    return fallback_result_fn(work_id, copy.deepcopy(initial_state))
                raise