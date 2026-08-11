# Starter kit — adopt the Agent Diff Gate in your project

Copy the pieces you need. The gate itself is `check_diff.py` — one file,
stdlib only, offline.

## What to copy

| Piece | Copy to | Purpose |
|---|---|---|
| `check_diff.py` (repo root of the gate) | your repo root | the gate |
| `hooks/pre-commit-gate.sh` | `.git/hooks/pre-commit` (+ `chmod +x`) | block commits with findings |
| `hooks/git-commitmsg-hook.sh` | `.git/hooks/commit-msg` (+ `chmod +x`) | log-before-fix `AREA:` gate |
| `hooks/block-no-verify-hook.sh` | `hooks/` (for the Claude hook) | blocks `git commit --no-verify` |
| `CLAUDE.md` (this folder) | repo root as `CLAUDE.md` | Claude Code reads it every session |
| `claude-settings.json` (this folder) | `.claude/settings.json` | Claude Code runs the gate on every commit tool call |
| `cursor-gate.mdc` (this folder) | `.cursor/rules/gate.mdc` | Cursor always-on rule |

## 1. The gate

```sh
cp check_diff.py /path/to/your/repo/
python check_diff.py --list-rules   # see what it checks
python check_diff.py --staged       # manual run before committing
```

## 2. Git hooks (hard enforcement for everyone — humans and agents)

```sh
cp hooks/pre-commit-gate.sh .git/hooks/pre-commit
cp hooks/git-commitmsg-hook.sh .git/hooks/commit-msg
chmod +x .git/hooks/pre-commit .git/hooks/commit-msg
```

- `pre-commit` runs `check_diff.py --staged` and aborts the commit on
  findings (empty staged diffs and clean code pass).
- `commit-msg` blocks code commits whose message lacks an `AREA:` marker
  matching a logged entry in `errors.txt` — log before you fix.
- ⚠️ `git commit --no-verify` skips both. The Claude Code hook and the
  `block-no-verify` git wrapper close that bypass (see the gate repo's
  `hooks/README.md`).

## 3. Agent instructions

Copy `CLAUDE.md` to your repo root. Claude Code reads it automatically at
session start; Cursor reads `AGENTS.md` and `.cursor/rules/`. It covers
the mandatory gate rule, the log-before-fix flow, and the commit
convention.

## 4. Claude Code hooks (the agent can't skip the gate)

```sh
mkdir -p .claude hooks
cp claude-settings.json .claude/settings.json
cp hooks/pre-commit-gate.sh hooks/
cp hooks/block-no-verify-hook.sh hooks/
```

Claude Code then runs the gate before every `GitCommit` tool call (blocked
with the report if it fails) and blocks `--no-verify` Bash calls.

## 5. Cursor

```sh
mkdir -p .cursor/rules
cp cursor-gate.mdc .cursor/rules/gate.mdc
```

Cursor has no tool-intercepting hooks, so enforcement is the git hooks in
step 2; the rule makes the agent comply voluntarily.

## Env config (all optional)

| Env var | Meaning |
|---|---|
| `PYTHON` | interpreter (default `python3`, then `python`) |
| `AGENT_DIFF_GATE_DIR` | where `check_diff.py` lives, if not the repo root |
| `AGENT_DIFF_GATE_ARGS` | extra gate args, e.g. `--fail-on medium` or `--exclude *_test*` (unquoted; globbing is off) |
| `AGENT_DIFF_GATE_OFF=1` | deliberate bypass (escape hatch) |

> **Fail-closed by design:** if `check_diff.py` is not at the repo root, the
> hook blocks every commit until you set `AGENT_DIFF_GATE_DIR` — that is
> intentional (a gate that can't run must not silently pass).
