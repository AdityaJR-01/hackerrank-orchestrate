"""
Team-created evaluation cases for Ghost Data Still Exists.

These six cases target the specific traps called out in problem_statement.md:
non-deletion intent, post-audit_at evidence contamination, failover-replica
drift, historical identifiers, policy retention, and account-tombstone redaction.

Each case is asserted structurally against the deterministic engine (no model
calls). Run from the repository root:

    PYTHONPATH=code python3 code/evaluation/run_custom_cases.py
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

from data_loader import DatasetIndex  # noqa: E402
from policy_engine import is_deletion, solve_case  # noqa: E402

DATASET = ROOT / "dataset"


def load_cases():
    samples = {r["case_id"]: r for r in csv.DictReader(
        (DATASET / "sample_deletion_requests.csv").open(encoding="utf-8-sig"))}
    tests = {r["case_id"]: r for r in csv.DictReader(
        (DATASET / "deletion_requests.csv").open(encoding="utf-8-sig"))}
    return {**tests, **samples}


def ops(steps):
    return [(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["evidence_id"]) for s in steps]


def main():
    index = DatasetIndex(DATASET)
    all_rows = list(csv.DictReader((DATASET / "deletion_requests.csv").open(encoding="utf-8-sig"))) + \
        list(csv.DictReader((DATASET / "sample_deletion_requests.csv").open(encoding="utf-8-sig")))
    index.link_by_activity([r for r in all_rows if is_deletion(r["request_text"])])
    cases = load_cases()
    results = []

    # 1. Non-deletion intent (data portability request) must never authorize work.
    r = cases["case_535"]
    status, steps, _ = solve_case(index, r)
    results.append((
        "custom_case_01 non-deletion intent -> NOT_APPLICABLE, []",
        status == "NOT_APPLICABLE" and steps == [] and not is_deletion(r["request_text"]),
        f"status={status}, steps={len(steps)}",
    ))

    # 2. Temporal cutoff: case_26 audit_at=2026-09-15 must be COMPLETE from evidence_92
    #    and must never cite the later evidence_02 bundle (captured 2026-09-17).
    r = cases["case_26"]
    status, steps, _ = solve_case(index, r)
    cited = {s["evidence_id"] for s in steps}
    results.append((
        "custom_case_02 post-audit evidence never leaks into a COMPLETE verdict",
        status == "COMPLETE" and "evidence_02" not in cited and "evidence_92" in cited,
        f"status={status}, cited={sorted(cited)}",
    ))

    # 3. Replication drift: primary profile deleted but failover replica (evidence_54)
    #    still holds account_005 -> INCOMPLETE with a cited finding and remediation.
    r = cases["case_05"]
    status, steps, _ = solve_case(index, r)
    o = ops(steps)
    results.append((
        "custom_case_03 failover replica drift -> REPORT/DELETE/VERIFY on account_005",
        status == "INCOMPLETE"
        and ("FINDING", "account_service", "account_005", "REPORT_REMAINING_RECORD", "evidence_54") in o
        and ("REMEDIATION", "account_service", "account_005", "DELETE_RECORD", "") in o
        and ("VERIFICATION", "account_service", "account_005", "VERIFY_RECORD_ABSENT", "") in o,
        f"status={status}",
    ))

    # 4. Historical identifier: case_10 was submitted under an old Yahoo address; the
    #    surviving replica support record must still be discovered.
    r = cases["case_10"]
    status, steps, _ = solve_case(index, r)
    o = ops(steps)
    results.append((
        "custom_case_04 historical email links surviving support_002 replica record",
        status == "INCOMPLETE"
        and any(x[2] == "support_002" and x[3] == "REPORT_REMAINING_RECORD" and x[4] == "evidence_61" for x in o)
        and any(x[2] == "account_010" and x[3] == "VERIFY_RECORD_ABSENT" for x in o),
        f"status={status}",
    ))

    # 5. Policy retention (rule_12): COMPLETE case keeps the security audit record and
    #    verifies it PRESENT with evidence, while profiles are absent and analytics anonymized.
    r = cases["case_21"]
    status, steps, _ = solve_case(index, r)
    o = ops(steps)
    results.append((
        "custom_case_05 retained security audit record survives a completed deletion",
        status == "COMPLETE"
        and any(x[1] == "security_service" and x[3] == "VERIFY_RECORD_PRESENT" and x[4] for x in o)
        and not any(x[3] in ("DELETE_RECORD", "REDACT_RECORD") and x[1] == "security_service" for x in o),
        f"status={status}",
    ))

    # 6. Tombstone rule (rule_15): stable user_id stays, direct identifiers exposed on
    #    tombstone_9178 -> REPORT_EXPOSED_PII / REDACT_RECORD / VERIFY_RECORD_REDACTED.
    r = cases["case_32"]
    status, steps, _ = solve_case(index, r)
    o = ops(steps)
    results.append((
        "custom_case_06 account tombstone keeps reference, redacts direct identifiers",
        status == "INCOMPLETE"
        and ("FINDING", "identity_service", "tombstone_9178", "REPORT_EXPOSED_PII", "evidence_51") in o
        and ("REMEDIATION", "identity_service", "tombstone_9178", "REDACT_RECORD", "") in o
        and ("VERIFICATION", "identity_service", "tombstone_9178", "VERIFY_RECORD_REDACTED", "") in o,
        f"status={status}",
    ))

    passed = 0
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name} ({detail})")
        passed += int(ok)
    print(f"\n{passed}/{len(results)} custom evaluation cases passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
