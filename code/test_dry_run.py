"""
Deterministic smoke test for the Ghost Data Still Exists engine.

Replaces the starter LLM-harness torture test: the shipped prediction path is
fully deterministic, so the "dry run" verifies repeatability, contract
validity, and representative policy decisions without any model calls or
third-party dependencies.

Run from the repository root:

    python3 code/test_dry_run.py
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))

from data_loader import DatasetIndex  # noqa: E402
from policy_engine import is_deletion, solve_case  # noqa: E402
from validate_and_evaluate import OutputValidator  # noqa: E402


def main() -> int:
    dataset = ROOT / "dataset"
    requests = list(csv.DictReader((dataset / "deletion_requests.csv").open(encoding="utf-8-sig")))
    samples = list(csv.DictReader((dataset / "sample_deletion_requests.csv").open(encoding="utf-8-sig")))

    index = DatasetIndex(dataset)
    index.link_by_activity([r for r in requests + samples if is_deletion(r["request_text"])])

    # 1. Determinism: two full passes produce byte-identical decisions.
    first = {r["case_id"]: solve_case(index, r) for r in requests}
    second = {r["case_id"]: solve_case(index, r) for r in requests}
    assert first == second, "engine is not deterministic across runs"
    print("[PASS] 1. deterministic reruns are identical")

    # 2. Every evaluation case resolves to a legal verdict.
    assert all(st in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"} for st, _, _ in first.values())
    assert len(first) == 518
    print("[PASS] 2. all 518 cases produce a legal deletion_status")

    # 3. Non-deletion intent yields empty step arrays.
    na = [cid for cid, (st, steps, _) in first.items() if st == "NOT_APPLICABLE"]
    assert na == [f"case_{i}" for i in range(533, 543)]
    assert all(first[cid][1] == [] for cid in na)
    print(f"[PASS] 3. exactly the 10 non-deletion cases -> NOT_APPLICABLE []: {na}")

    # 4. Representative policy behaviours on known samples.
    gold_checks = {
        "case_05": ("INCOMPLETE", "account_service", "account_005", "REPORT_REMAINING_RECORD", "evidence_54"),
        "case_21": ("COMPLETE", "security_service", "audit_record_3737", "VERIFY_RECORD_PRESENT", "evidence_92"),
        "case_32": ("INCOMPLETE", "identity_service", "tombstone_9178", "REPORT_EXPOSED_PII", "evidence_51"),
    }
    sample_rows = {r["case_id"]: r for r in samples}
    for cid, (status, sys_id, rid, op, ev) in gold_checks.items():
        st, steps, _ = solve_case(index, sample_rows[cid])
        assert st == status
        assert any(s["system_id"] == sys_id and s["resource_id"] == rid
                   and s["operation"] == op and s["evidence_id"] == ev for s in steps), cid
    print("[PASS] 4. replica-drift, retention, and tombstone policy cases correct")

    # 5. Written output passes the structural validator.
    out = ROOT / "cache" / "dry_run_output.csv"
    out.parent.mkdir(exist_ok=True)
    rows = [
        {"case_id": cid, "deletion_status": st, "steps_json": json.dumps(steps, separators=(",", ":"))}
        for cid, (st, steps, _) in first.items()
    ]
    with out.open("w", encoding="utf-8", newline="\n") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    ok, errors, _ = OutputValidator().validate(out, dataset / "deletion_requests.csv")
    assert ok, errors
    print("[PASS] 5. generated output passes OutputValidator (518 rows)")

    print("\nAll deterministic dry-run checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
