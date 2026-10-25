"""
Deterministic entry point for the Ghost Data Still Exists deletion-audit agent.

Run from the repository root:

    python3 code/main.py

This produces the submission file `output.csv` (518 rows) using only the Python
standard library. No model calls, network access, credentials, or third-party
packages are required: intent classification, identity resolution across
current and historical identifiers, point-in-time evidence reconstruction,
deletion_rules.csv policy decisions, and step ordering are all deterministic.

The optional multi-provider LLM harness (llm_harness.py + tx_engine.py) is kept
in the codebase as an experimental extraction layer but is not part of the
final prediction path.
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "code"))

from data_loader import DatasetIndex  # noqa: E402
from policy_engine import is_deletion, solve_case, write_csv  # noqa: E402
from validate_and_evaluate import OutputValidator  # noqa: E402


def main() -> int:
    dataset = ROOT / "dataset"
    with (dataset / "deletion_requests.csv").open(encoding="utf-8-sig") as f:
        requests = list(csv.DictReader(f))

    index = DatasetIndex(dataset)
    index.link_by_activity([r for r in requests if is_deletion(r["request_text"])])

    rows = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
    for case in requests:
        status, steps, _ = solve_case(index, case)
        status_counts[status] += 1
        rows.append(
            {
                "case_id": case["case_id"],
                "deletion_status": status,
                "steps_json": json.dumps(steps, separators=(",", ":")),
            }
        )

    out_path = ROOT / "output.csv"
    write_csv(out_path, rows)

    ok, errors, _ = OutputValidator().validate(out_path, dataset / "deletion_requests.csv")
    print(f"Wrote {len(rows)} rows to {out_path}")
    print("Status distribution:", status_counts)
    if not ok:
        for err in errors[:20]:
            print("  [ERROR]", err)
        return 1
    print("Output validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
