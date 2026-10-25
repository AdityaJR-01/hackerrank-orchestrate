# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.

---

# Solution: deterministic deletion-audit engine

The shipped solution is a **fully deterministic, zero-model-call** audit
engine. It uses only the Python 3.11 standard library, so `output.csv` is
byte-identical across reruns and costs zero tokens (see
`code/evaluation/usage_report.md`).

## Run

```bash
# Full 518-case run -> root output.csv (writes and self-validates)
python3 code/main.py

# Score against the 32 public gold samples -> code/evaluation/evaluation_report.md
PYTHONPATH=code python3 code/policy_engine.py

# Structural validation of any output file
python3 code/validate_and_evaluate.py --output output.csv --input dataset/deletion_requests.csv

# Six team-created custom evaluation cases
PYTHONPATH=code python3 code/evaluation/run_custom_cases.py
```

## Architecture

```text
dataset/*.csv + dataset/evidence/* (94 files)
  |
  v
code/data_loader.py
    Identity graph: user_identities + user_audit_log historical emails/phones/hashes
                    + LINK_RESOURCE_IDENTITY activities + in-evidence identifiers
    Parsers: SQLite SQL dumps, JSON bundles/exports, logs (key=value, bracket,
             escaped-JSON), handover text, PDFs, screenshot fact tables
    All observations are timestamped from the evidence MANIFEST captured_at
    and indexed per (system, resource) for temporal state_at(audit_at) queries
  |
  v
code/policy_engine.py
    1. Intent gate: explicit-negation regex -> NOT_APPLICABLE (exactly cases 533-542)
    2. Resource universe: identity-linked resources observed at/after requested_at
    3. State reconstruction at audit_at (latest covering evidence wins)
    4. deletion_rules.csv (rules 01-15) -> FINDING / REMEDIATION / VERIFICATION ops
    5. Deterministic ordering: phase, operation table order, system_id, resource_id
  |
  v
output.csv (518 rows, validated by code/validate_and_evaluate.py)
```

## Key dataset traps and how the engine handles them

1. **Workflow claims vs. evidence.** `reported_status` and worker
   `reported_result` are never treated as proof; the verdict comes from
   point-in-time evidence state compared with `deletion_rules.csv`.
2. **Post-`audit_at` contamination.** Manifest capture times gate every
   observation; evidence captured after a case's cutoff cannot change it.
3. **Replication drift.** Failover/read replicas are parsed independently, so
   a profile deleted from primary but present in a replica (e.g. `account_005`
   in `evidence_54`) is correctly reported as remaining.
4. **Historical identifiers.** Old emails/phones from `user_audit_log.csv`
   resolve downstream records that no longer display the current identity
   (100 evaluation requests use non-current emails).
5. **Identity-less worker events.** Deletion-worker rows without identifiers
   are reattached via off-hour proximity and stable-order 1:1 matching inside
   equal-size `(day, mirrored-result)` groups.
6. **Parallel-run ambiguity.** Null-identifier analytics in interleaved
   parallel deletion runs are left unclaimed rather than guessed, so the
   engine produces zero extraneous steps (recall-only gaps remain where the
   participant data genuinely cannot ground an owner).
7. **Retention.** Security audit logs (rule 12), legal holds (rule 13),
   backups kept with restore blocked (rule 14), and tombstones redacted to a
   stable `user_id` (rule 15) are verified PRESENT/BLOCKED/REDACTED, never
   deleted.

## Results on the 32 public samples

| Metric | Score |
| :-- | --: |
| Case-level deletion-status accuracy | **100.0%** (32/32) |
| Step-level set F1 | **96.95%** |
| Field-level accuracy (operation/state/evidence) | **94.70%** |
| Exact sequence accuracy | **75.00%** (24/32) |
| Composite (0.35/0.35/0.30) | **91.43%** |
| Full-dataset structural validation (518 rows) | **PASS** |
| Custom evaluation cases | **6/6 PASS** |

The eight non-exact sequences differ only by missing verification steps whose
resource ids are either absent from all participant files or un attributable
inside parallel readback batches; full analysis is in
`code/evaluation/evaluation_report.md`.

## Code map

| File | Role |
| :-- | :-- |
| `code/main.py` | Deterministic entry point; writes and validates root `output.csv` |
| `code/data_loader.py` | Identity graph, 94-file evidence parser, activity claiming, temporal queries |
| `code/policy_engine.py` | Intent gate, policy decisions, step construction/ordering, sample scoring |
| `code/validate_and_evaluate.py` | Structural output validator + sample scorer and report generator |
| `code/evaluation/run_custom_cases.py` | Six executable custom evaluation cases |
| `code/evaluation/custom_cases.md` | Custom-case specifications |
| `code/evaluation/evaluation_report.md` | Metrics, discrepancy log, iteration log, methodology |
| `code/evaluation/usage_report.md` | Zero-token/cost accounting for the deterministic run |
| `code/llm_harness.py`, `code/tx_engine.py` | Optional experimental LLM extraction harness (not used in the final path) |
