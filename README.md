# Ghost Data Still Exists

> A deletion-audit agent that proves whether a deleted customer is really gone. It reconstructs what every
> system held at audit time from the evidence itself, not from the workflow's "Complete", and returns the
> exact remediation and verification steps needed to finish the job.

Built for HackerRank Orchestrate (October 2026). The full challenge contract is in
[`problem_statement.md`](./problem_statement.md).

## The problem

Northstar Shop's deletion workflow marks requests "Complete" while personal data survives in replicas,
search indexes, support tickets, analytics, exports, backups and logs, and sync or restore jobs can quietly
bring deleted data back. For each of 518 requests the agent must decide whether deletion was actually
requested, find every remaining copy and recreation risk as of `audit_at`, and return `COMPLETE`,
`INCOMPLETE` or `NOT_APPLICABLE` with ordered findings, remediation and verification steps that follow
`deletion_rules.csv`, while keeping the records the policy says must be retained.

## Design philosophy: the evidence decides, the code enforces

> A deletion audit is a proof, not a guess. If the evidence cannot ground a step, the step does not ship.

The obvious design is a model in the loop for every case. I went the other way: **no model calls at
runtime.** The evidence is structured (SQLite dumps, JSON exports, key=value logs, handover text) or fixed
(four PDFs, eleven console screenshots), and the output contract is strict about step order, evidence ids and
states. Rules written in code meet that contract exactly, cost nothing to run and give the same answer every
time.

Models were used where they actually help: during development, to read the PDFs and screenshots once. Those
facts are stored as fixed tables in `code/data_loader.py`, so runtime never has to interpret an image again.

## How it works

```
deletion request
  │
  ├─▶ intent gate ─────── unsubscribe · export · correction → NOT_APPLICABLE, []
  │
  ├─▶ identity graph ──── current + historical emails, phones, hashes, user_ids
  │       └─ extended by LINK_RESOURCE_IDENTITY activities and identifiers found in evidence
  │
  ├─▶ evidence index ──── 94 files: SQL primaries + replicas · JSON · logs · handover · PDF/PNG facts
  │       └─ every observation stamped with its manifest captured_at
  │
  ├─▶ state at audit_at ─ latest covering evidence wins · absence must be proven
  │
  └─▶ policy + ordering ─ deletion_rules 01-15 → FINDING / REMEDIATION / VERIFICATION
          └─ phase · operation order · system_id · resource_id → output.csv (self-validated)
```

- **Claims are not evidence.** `reported_status` and worker `reported_result` are never treated as proof.
  Every verdict comes from point-in-time evidence compared with `deletion_rules.csv`.
- **The manifest clock governs.** Timestamps inside snapshots can differ from when the file was captured, so
  every observation is gated by manifest `captured_at <= audit_at`. Evidence from after the audit can never
  change the verdict (the case_26 trap).
- **Latest covering evidence wins.** When old and new evidence disagree, the newest observation on or before
  `audit_at` decides (the case_07 screenshot-versus-PDF trap).
- **Absence must be proven.** A record missing from a partial extract proves nothing. ABSENT is concluded only
  from a snapshot that fully covers the system, such as the full-profile replica `evidence_54`.
- **Replicas are read separately.** A profile deleted from the primary but still in a failover replica
  (`account_005`) is reported as remaining.
- **Old identities still count.** Historical emails and phones from `user_audit_log.csv` resolve downstream
  records that no longer show the current identity.
- **Anonymous worker events get an owner.** Deletion-worker rows carry no identifier. They are reattached by
  15-minute proximity for off-hour runs, then by stable-order 1:1 matching inside equal-size
  `(day, mirrored-result)` groups.
- **Precision over guessing.** Analytics records with no identifier, inside parallel runs that interleave in
  the same minute, are left unclaimed rather than assigned speculatively. A wrong step costs more than a
  missing one.
- **Retention is verified, never deleted.** Security audit logs (rule 12), legal holds (rule 13), backups kept
  with restore blocked (rule 14) and tombstones reduced to a stable `user_id` (rule 15) are verified PRESENT,
  BLOCKED or REDACTED.

## At a glance

| | |
| :-- | :-- |
| Runtime | Python 3.11+ standard library only (tested on 3.14.7) |
| Full 518-case run | about 0.75 s on one core, including parsing all 94 evidence files |
| Determinism | byte-identical output across reruns and from a clean unzip of `code.zip` |
| Model calls / tokens / cost | 0 / 0 / $0 (`evaluation/usage_report.md`) |
| Output | 518 rows in input order: 175 COMPLETE · 333 INCOMPLETE · 10 NOT_APPLICABLE |

## Results

On the 32 public sample cases:

| Metric | Score |
| :-- | --: |
| Deletion-status accuracy | **100.0%** (32/32) |
| Step-level set F1 | **96.95%** |
| Field-level accuracy (operation / state / evidence) | **94.70%** |
| Exact sequence accuracy | **75.00%** (24/32) |
| Composite (0.35 status + 0.35 F1 + 0.30 sequence) | **91.43%** |
| Structural validation, all 518 rows | **PASS** |
| Custom evaluation cases | **6/6 PASS** |

The six custom cases cover non-deletion intent, the post-`audit_at` cutoff, replica drift, historical
identifiers, security-log retention and tombstone redaction. They were confirmed to fail when they should:
with the `audit_at` gate disabled, the post-cutoff case fails (5/6).

## Known limitations

- **Two ids no file contains.** Gold answers for cases 18 and 20 verify `audit_record_6645` and
  `audit_record_5569`, which appear in no participant file or activity row.
- **Ambiguous analytics records.** Cases 03, 21 and 25-28 each miss one analytics verification, the
  deliberate cost of not guessing.
- **Tuned on the samples.** Accuracy on the hidden answers is unknown. One rule was fitted to the samples:
  analytics hits found in logs map to DELETE, analytics profiles found in readback evidence map to ANONYMIZE
  (case_12).
- **Fixed document facts.** New or changed PDFs and screenshots would need their fact tables updated.
- **Silent systems.** Cache, profile, notification and archive systems appear in the data, but no sample
  answer has a step for them and the engine emits none.

Full discrepancy and iteration logs: [`evaluation/evaluation_report.md`](./evaluation/evaluation_report.md).

## Quickstart

No install step, API keys or network access. From the repository root, with `dataset/` in place:

```bash
python3 code/main.py                                          # 518 cases → output.csv, self-validated
PYTHONPATH=code python3 code/policy_engine.py                 # score the 32 samples, regenerate the report
PYTHONPATH=code python3 code/evaluation/run_custom_cases.py   # six custom cases
python3 code/validate_and_evaluate.py --output output.csv --input dataset/deletion_requests.csv
```

`requirements.txt` lists optional packages, commented out, used only by the unused experimental harness.

## Repository layout

```
code/
  main.py                   entry point: writes and validates output.csv
  data_loader.py            identity graph, evidence parsers, activity claiming, state_at queries
  policy_engine.py          intent gate, policy decisions, step construction and ordering, sample scoring
  validate_and_evaluate.py  structural validator, sample scorer, report generator
  evaluation/               evaluation_report.md · usage_report.md · custom_cases.md · run_custom_cases.py
  llm_harness.py, tx_engine.py   experimental LLM harness from the starter scaffold (not used)
evaluation/                 identical copies of the three reports (problem-statement path)
dataset/                    challenge data (provided, not in code.zip)
output.csv                  final predictions
log.txt                     development transcript
problem_statement.md        the original task spec
```

`code.zip` contains `README.md`, `requirements.txt`, `code/` and `evaluation/`. A clean unzip with
`dataset/` copied in reproduces `output.csv` byte for byte.

## How it was built

`log.txt` follows AGENTS.md section 5 and names the exact tool and model for every entry: the Gemini web app
(`gemini-3.1-pro-preview`) for exploring the repository and data, Google AI Studio (`gemini-4-argon`) for
evidence triage and the first engine build, and claude.ai (`claude-sonnet-5-5`) for review, verification and
packaging. Some entries were backfilled after the fact, as noted at the top of the file. Prompts that were
summarised rather than preserved are marked `[RECONSTRUCTED]`.

## Tech

Python 3.11+ standard library: `csv` · `json` · `re` · `sqlite3` · `pathlib` · `dataclasses`. No model calls,
third-party packages or network access at runtime.
