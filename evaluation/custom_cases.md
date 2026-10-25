# Custom Evaluation Cases

Six team-created evaluation cases exercise the traps called out in
`problem_statement.md`. They are implemented as executable assertions in
[`run_custom_cases.py`](./run_custom_cases.py) and run against the real
deterministic engine and real participant evidence (no fabricated data, no
golden-label shortcuts).

Run them from the repository root:

```bash
PYTHONPATH=code python3 code/evaluation/run_custom_cases.py
# 6/6 custom evaluation cases passed
```

| Case | Trap targeted | Input (real case id) | Required behaviour | Asserts |
| :-- | :-- | :-- | :-- | :-- |
| `custom_case_01` | Non-deletion intent (data portability/export request) | `case_535` — *"I'd like to download my account information in a portable format"* | No deletion or verification is authorized | `NOT_APPLICABLE`, `steps_json == []`, intent gate returns non-deletion |
| `custom_case_02` | Post-`audit_at` evidence contamination | `case_26`, `audit_at=2026-09-15T12:00Z` | The 2026-09-17 bundle (`evidence_02`) must not influence the answer | Verdict `COMPLETE`, `evidence_02` never cited, all citations are `evidence_92` |
| `custom_case_03` | Replication drift: failover replica still holds a "deleted" profile | `case_05` | The surviving `account_005` row in `evidence_54` overrides the worker's `SUCCESS` claim | `INCOMPLETE`; FINDING `REPORT_REMAINING_RECORD` citing `evidence_54`, `DELETE_RECORD` remediation with `evidence_id=""`, then `VERIFY_RECORD_ABSENT` |
| `custom_case_04` | Historical identifier (old Yahoo address) + undeleted support replica | `case_10` | Records keyed to the previous address must still be discovered | `INCOMPLETE`; `support_002` `REPORT_REMAINING_RECORD` citing `evidence_61`; `account_010` absent-verification included |
| `custom_case_05` | Policy retention (rule_12, security audit log) | `case_21` | Retained records stay available and are never deleted/redacted | `COMPLETE`; `VERIFY_RECORD_PRESENT` on the audit record with a non-empty evidence id; no destructive op targeting `security_service` |
| `custom_case_06` | Account tombstone rule (rule_15): keep stable `user_id`, remove direct identifiers | `case_32` | Exposed PII on `tombstone_9178` must be redacted, not deleted | `INCOMPLETE`; `REPORT_EXPOSED_PII` (cites `evidence_51`) → `REDACT_RECORD` (`""`) → `VERIFY_RECORD_REDACTED` (`""`) |

## Why these six

1. They cover all three verdict types (`COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`).
2. They hit every remediation family used by the engine: `DELETE_RECORD`,
   `REDACT_RECORD`, `ANONYMIZE_RECORD`, `DISABLE_DATA_FLOW`, `BLOCK_RESTORE`
   (the last two are exercised by sample cases 11/14/15/29/30 and by the
   full-dataset run, alongside these custom checks).
3. They test the temporal contract (`audit_at` cutoff), the identity graph
   (historical emails), the evidence-citation contract, and the two RETAIN
   policies (security audit logs and tombstones).
