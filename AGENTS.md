# Agent instructions

This repo uses the **Agent Diff Gate** system — your working instructions
live in three companion files. This file is read by AI coding agents that
honor the `AGENTS.md` convention (Claude Code, Codex, and others); if yours
doesn't, paste this into your system prompt instead.

Follow this exactly:

## Every session

1. Start by running `python start.py` (Windows: `start.bat`). It health-checks
   the error log and prints the reading order, the open errors, and the
   latest session note.
2. Read, in order:
   1. `rules.txt`  — the RULES: how to behave, conventions, non-negotiables
   2. `errors.txt` — check BEFORE debugging and BEFORE writing code
   3. `notes.txt`  — general context + session notes

## Mandatory rules (no exceptions)

- **CHECK BEFORE CODING** — review `errors.txt` before writing or modifying
  any code, so past mistakes are not repeated.
- **LOG BEFORE FIXING** — found an error? Do NOT fix it immediately. Log it
  first:
  ```sh
  python check_diff.py --add --area "<what broke>" --error "<symptom>" --cause "<root cause>"
  ```
  Only after the entry exists may you apply the fix. Verify with:
  ```sh
  python check_diff.py --has-entry "<what broke>"
  ```

## Committing

The git commit-msg hook blocks code commits whose message lacks an
`AREA: <text>` marker matching a logged entry. Convention:

```sh
git commit -m "fix <thing> (AREA: <what broke>)"
```

- Docs/notes-only commits pass automatically.
- Never use `git commit --no-verify` — it skips every hook, including this
  gate. If the hook blocks you, the error isn't logged; log it first, then
  commit again.
- **CI re-enforces the gate server-side** — the workflow re-runs
  `check_diff.py --check-commit` on every push to master.
- If your harness supports agent hooks (Claude Code, VS Code), install the
  blockers in `hooks/` (see `hooks/README.md`).

## Housekeeping

- Keep entries short and factual. Write the CAUSE before fixing.
- End sessions with a dated note in `notes.txt`:
  `SESSION NOTE (YYYY-MM-DD): TITLE`.
- Archive old FIXED entries occasionally:
  `python check_diff.py --archive-days 30 --apply`.

## The product

`check_diff.py` is a pre-commit quality gate for AI-generated code. When
you change a rule, update BOTH its positive and negative tests in
`_test_diff.py` — a rule that fires on clean code is worse than no rule.
Keep all 125 tests green and the README test count in sync (the CI drift
guard enforces it).
