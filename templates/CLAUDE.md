<!--
  CLAUDE.md — template for projects adopting the Agent Diff Gate.
  Copy this file to your repo root as CLAUDE.md. Adjust the paths if
  check_diff.py is not at the repo root (see AGENT_DIFF_GATE_DIR).
-->
# CLAUDE.md — project instructions

This project uses **Agent Diff Gate** (`check_diff.py`), a pre-commit quality
gate for AI-generated code. It scans every diff before it lands and blocks
the patterns that cause churn and vulnerabilities: hardcoded secrets,
swallowed errors, missing error handling, duplicate logic, ignored existing
patterns, unsafe execution, SQL injection, and more. It also carries the
**log-before-fix** discipline: no fix lands unless the error it fixes is
logged first.

The gate is mandatory. Follow this exactly.

---

## 1. Every session — start with a health check

1. Run the gate's health check and confirm the error log is healthy:
   ```sh
   python check_diff.py --log
   ```
2. Read these files in order **before writing any code**:
   - `AGENTS.md` — the rules, conventions, non-negotiables
   - `errors.txt` — every past error and its cause (CHECK BEFORE CODING)
   - `notes.txt` — session notes and project context

---

## 2. Mandatory rules (no exceptions)

- **CHECK BEFORE CODING** — review `errors.txt` before writing or modifying
  any code, so past mistakes are not repeated.
- **RUN THE GATE BEFORE COMMITTING** — before every commit:
  ```sh
  python check_diff.py --staged
  ```
  If it exits non-zero, **fix every finding and re-run until it passes**.
  Never commit with findings, and never silence the gate with
  `--warn-only` to sneak a commit through.
- **LOG BEFORE FIXING** — found an error? Do NOT fix it immediately. Log
  it first:
  ```sh
  python check_diff.py --add --area "<what broke>" \
    --error "<symptom>" --cause "<root cause>"
  ```
  Write the CAUSE **before** you start fixing — if you can't explain why it
  broke, you haven't understood it yet. Verify the entry exists with:
  ```sh
  python check_diff.py --has-entry "<what broke>"
  ```
  Only then may you apply the fix.

---

## 3. The gate — quick reference

```sh
python check_diff.py                # working-tree diff
python check_diff.py --staged       # staged changes (use before every commit)
python check_diff.py --range A B    # commit range (like a PR review)
git diff | python check_diff.py --stdin
python check_diff.py --list-rules   # all rules incl. rules.d/ plugins
```

**Reading the verdict:**
- `GATE: PASS` (exit 0) — safe to commit.
- `GATE: FAIL` (exit 1) — findings at/above the threshold. Fix them.
- Exit 2 — usage error.

**Tuning (rarely needed — defaults are right):**
- `--fail-on high|medium|low|none` — how strict the gate is
- `--rule R1,R2` — only run specific rules
- `--exclude "*.test.py"` — skip matching files
- `--json` — machine-readable output

---

## 4. Committing — the AREA marker

The commit-msg hook blocks code commits whose message lacks an
`AREA: <text>` marker that matches a logged entry:

```sh
git commit -m "fix <thing> (AREA: <what broke>)"
```

- The AREA text must match (substring) an entry already logged in
  `errors.txt` — log before you fix, then reference it in the commit.
- Docs/notes-only commits pass automatically (no AREA needed).
- **Never use `git commit --no-verify`** — it skips every hook. If the hook
  blocks you, the error isn't logged: log it first, then commit again.

---

## 5. Housekeeping

- Keep log entries short and factual. CAUSE first, then the fix.
- End each working session with a dated note in `notes.txt`:
  `SESSION NOTE (YYYY-MM-DD): TITLE` + a few factual bullets.
- Archive old FIXED entries occasionally:
  ```sh
  python check_diff.py --archive-days 30 --apply
  ```
- If you add a rule (in `rules.d/`), test it — positive case AND negative
  case (a rule that fires on clean code is worse than no rule).

---

## 6. When the gate blocks you

1. Read the report — file, line, rule, suggestion.
2. Fix the code properly (not by weakening the gate).
3. Re-run `python check_diff.py --staged` until `GATE: PASS`.
4. If the finding is a false positive, don't disable the rule — fix the
   rule (or file a `rules.d/` override) with a test.
