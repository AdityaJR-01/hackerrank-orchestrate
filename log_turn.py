#!/usr/bin/env python3
"""
AGENTS.md section 2 & 5 logger for HackerRank Orchestrate (October 2026).
Appends UTF-8 LF entries to the log.txt beside AGENTS.md.

Usage:
  python3 log_turn.py --start --tool "<harness>" --model "<exact-model-id>"
  python3 log_turn.py --tool "<harness>" --model "<exact-model-id>" \\
      --title "Short title" --prompt "Exact user prompt" \\
      --summary "2-5 sentence summary" --actions "Edited X" "Ran Y"

Both --tool and --model are mandatory on every invocation: AGENTS.md forbids
blank, generic, inferred, or placeholder values for either field.
"""
import argparse
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

SECRET_PATTERNS = [
    re.compile(r"(gsk_[A-Za-z0-9]{20,})"),
    re.compile(r"(nvapi-[A-Za-z0-9_\-]{20,})"),
    re.compile(r"(sk-or-v1-[A-Za-z0-9]{20,})"),
    re.compile(r"(AIza[0-9A-Za-z_\-]{30,})"),
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?"),
]


def redact_secrets(text: str) -> str:
    out = text
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def resolve_repo_root() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (Path.cwd(), here, here.parent):
        if (candidate / "AGENTS.md").exists():
            return candidate.resolve()
    return Path.cwd().resolve()


def get_git_branch(repo_root: Path) -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root, capture_output=True, text=True, timeout=3,
        )
        return res.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _require(label: str, value: str) -> str:
    value = (value or "").strip()
    if not value or value.lower() in {"unknown", "none", "null", "placeholder"}:
        raise SystemExit(f"Error: --{label} is mandatory and must be an exact, non-generic value.")
    return value


def append_session_start(log_path: Path, repo_root: Path, tool: str, model: str, remaining: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = (
        f"## [{ts}] SESSION START\n\n"
        f"tool={tool}\nmodel={model}\n"
        f"Repo Root: {repo_root}\nBranch: {get_git_branch(repo_root)}\n"
        f"Worktree: main\nParent Agent: none\nLanguage: py\nTime Remaining: {remaining}\n\n"
    )
    with log_path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(entry)
    print(f"[LOG] Appended SESSION START to {log_path}")


def append_turn_entry(log_path, repo_root, tool, model, title, prompt, summary, actions) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    action_lines = "\n".join(f"- {redact_secrets(a)}" for a in actions) if actions else "- Inspected repository"
    entry = (
        f"## [{ts}] {redact_secrets(title.strip())[:80]}\n\n"
        f"User Prompt (verbatim, secrets redacted):\n{redact_secrets(prompt.strip())}\n\n"
        f"Agent Response Summary:\n{redact_secrets(summary.strip())}\n\n"
        f"Actions:\n{action_lines}\n\n\n"
        f"Context:\ntool={tool}\nmodel={model}\n"
        f"branch={get_git_branch(repo_root)}\nrepo_root={repo_root}\n"
        f"worktree=main\nparent_agent=none\n\n"
    )
    with log_path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(entry)
    print(f"[LOG] Appended turn '{title.strip()[:80]}' to {log_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--remaining", default="not configured")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--title", default="Repository analysis")
    parser.add_argument("--prompt", default="")
    parser.add_argument("--summary", default="")
    parser.add_argument("--actions", nargs="*", default=[])
    args = parser.parse_args()

    tool = _require("tool", args.tool)
    model = _require("model", args.model)
    repo_root = resolve_repo_root()
    log_path = repo_root / "log.txt"

    if args.start:
        append_session_start(log_path, repo_root, tool, model, args.remaining)
    else:
        if not args.prompt or not args.summary:
            raise SystemExit("Error: --prompt and --summary are required for turn entries.")
        append_turn_entry(log_path, repo_root, tool, model, args.title, args.prompt, args.summary, args.actions)


if __name__ == "__main__":
    main()
