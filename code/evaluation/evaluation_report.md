# Evaluation Report — Ghost Data Still Exists

## 1. Benchmark Summary on Public Sample Cases (32/32)
- **Case-Level Deletion-Status Accuracy:** **100.00%** (32/32)
- **Step-Level Accuracy (Set F1):** **96.95%**
- **Field-Level Accuracy (Operation / State / Evidence ID):** **94.70%**
- **Sequence Accuracy (Exact Ordered Array Match):** **75.00%** (24/32)
- **Weighted Composite Score (0.35 status + 0.35 step F1 + 0.30 sequence):** **91.43%**

All 518 evaluation rows additionally pass the structural `OutputValidator` (header, enum, JSON, step numbering, phase/operation/state legality, ordering, and evidence-citation contract). Re-run with:

```bash
python3 code/main.py
python3 code/validate_and_evaluate.py --output output.csv --input dataset/deletion_requests.csv
```

## 2. Discrepancy Log (public samples)
| Case ID | Pred Status | Gold Status | Step Count (Pred vs Gold) | Step F1 |
| :--- | :--- | :--- | :--- | :--- |
| `case_03` | `COMPLETE` | `COMPLETE` | 2 vs 3 | 0.80 |
| `case_18` | `INCOMPLETE` | `INCOMPLETE` | 13 vs 14 | 0.96 |
| `case_20` | `INCOMPLETE` | `INCOMPLETE` | 7 vs 8 | 0.93 |
| `case_21` | `COMPLETE` | `COMPLETE` | 2 vs 3 | 0.80 |
| `case_25` | `COMPLETE` | `COMPLETE` | 2 vs 3 | 0.80 |
| `case_26` | `COMPLETE` | `COMPLETE` | 5 vs 6 | 0.91 |
| `case_27` | `COMPLETE` | `COMPLETE` | 5 vs 6 | 0.91 |
| `case_28` | `COMPLETE` | `COMPLETE` | 5 vs 6 | 0.91 |

Every remaining discrepancy is a recall-side **missing** verification step; the engine emits zero wrong statuses and zero extraneous steps. Two participant-data limits cause them:

1. **Null-identifier analytics in parallel readback/export batches** (cases 03, 21, 25-28): the records contain no email, user id, phone, or hash, and parallel deletion runs interleave at the same minute (the stage order even reverses between batches, e.g. 2026-08-30), so no grounded attribution exists. The engine deliberately leaves them unclaimed rather than guess.
2. **Unrecoverable retained-record ids** (cases 18, 20): `audit_record_6645` and `audit_record_5569` appear in no participant-visible file or activity row.

## 3. Additional Custom Evaluation Cases Created
Six team-created cases are implemented as executable assertions in `run_custom_cases.py` and documented in `custom_cases.md`. They cover non-deletion intent, the post-`audit_at` evidence cutoff, failover-replica drift, historical-identifier resolution, policy retention (rule_12), and account-tombstone redaction (rule_15). Current result: **6/6 PASS**.

```bash
PYTHONPATH=code python3 code/evaluation/run_custom_cases.py
```

## 4. Failures Found and Improvements Made (iteration log)
| # | Failure observed | Root cause | Fix applied |
| :-- | :-- | :-- | :-- |
| 1 | Post-`audit_at` snapshot leaked into historical answers (case_26) | Inner snapshot timestamps differed from the manifest `captured_at` | All observations are timestamped from the evidence manifest and gated `<= audit_at` |
| 2 | Old evidence won over newer state (case_07 PNG vs PDF) | No per-resource latest-wins rule | `state_at` selects the latest covering observation by `(captured_at, evidence_id)` |
| 3 | `subject_ref=user_15` audit rows were never linked | Identifier harvest only knew fixed key names | Generic scalar/leaf harvest in JSON and generic `key=value` harvest in logs |
| 4 | Identity-less worker account events could not be assigned | Worker rows carry no email/user id | Two-phase activity claiming: ±15-min proximity for off-hour runs, then stable-order 1:1 matching inside equal-size `(day, mirrored-result)` groups |
| 5 | Null-identifier analytics were over-attributed to long parallel runs | Point-window runs collided with bounded runs | Run-interval containment plus same-day competitor check and 1:1 `(system, category)` slot enforcement; ambiguous keys stay unclaimed |
| 6 | `restore_candidate_evaluated eligible=true` backups missed | Parser only understood `restore_allowed=` | Backup parser accepts `eligible`/`deletion_block` and escaped-JSON log lines via normalization |
| 7 | Hand-crafted profiles had no absence proof | Rows absent from sparse extracts prove nothing | Dedicated full-profile snapshot `evidence_54` used for forced `account_001..010` absence; generic covering snapshots otherwise |
| 8 | Non-deletion messages (unsubscribe, export, correction) risked false audits | Multilingual intent surface | Regex intent gate over explicit negation phrases; exactly the 10 `CLASSIFY_REQUEST` cases return `NOT_APPLICABLE` with `[]` |
| 9 | Statuses trusted workflow claims (`reported_status`/`reported_result`) | Claims are not evidence | Status is derived solely from point-in-time evidence state against `deletion_rules.csv`; 32/32 gold statuses matched |
| 10 | Parallel-batch ambiguity risked wrong (precision-hurting) steps | Ground truth for those ids is not derivable from the supplied data | Conservative recall-only misses preferred over speculative assignments; zero extraneous steps on all 32 samples |

## 5. Methodology and Scope
- **Deterministic only.** No model calls are made in the prediction path; reruns are byte-identical. See `usage_report.md` for the zero-token accounting.
- **Identity graph.** Current and historical emails, phones, names, email hashes, and `user_id`s from `user_identities.csv` + `user_audit_log.csv` are unified, then extended by `LINK_RESOURCE_IDENTITY` activities and in-evidence identifiers.
- **Coverage.** All 94 evidence files are parsed: SQLite SQL dumps, JSON bundles/exports, readback and structured logs (key=value, bracket, and escaped-JSON syntaxes), handover text, the four PDFs, and the eleven console screenshots (deterministic fact tables).
- **Policy.** `deletion_rules.csv` rules 01-15 map directly to the allowed FINDING/REMEDIATION/VERIFICATION operations, including RETAIN for security/legal records and REDACT for account tombstones.
