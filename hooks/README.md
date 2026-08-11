# Enforcement hooks — agent-diff-gate

Git hooks are **advisory**: `git commit --no-verify` skips every hook in
`.git/hooks/`. The layers below make the bypass deliberate instead of
silent, at the layers where agents actually live.

## Layers

| Layer | What it blocks | Where |
|-------|---------------|-------|
| pre-commit gate | findings in the staged diff (`check_diff.py --staged`) | `.git/hooks/pre-commit` |
| commit-msg gate | unlogged fixes (`AREA:` marker missing / not in errors.txt) | `.git/hooks/commit-msg` |
| git wrapper | `git commit --no-verify` / `-n` | `~/.local/bin/block-no-verify` + shell rc |
| Claude Code hook | `--no-verify` Bash tool calls | `.claude/settings.json` (PreToolUse) |
| VS Code agent hooks | `--no-verify` tool calls | `.github/hooks/` |
| CI (server-side) | unlogged fixes on every push | GitHub Actions `commit-gate` job |

The CI commit-gate job re-runs `check_diff.py --check-commit` on every
push to master — a `--no-verify` commit can pass locally but can never land
on master without naming a logged error.

## Install

```sh
./hooks/install.sh              # everything
./hooks/install.sh --git        # both git gates (pre-commit + commit-msg)
./hooks/install.sh --status     # what's installed
```

Idempotent; existing settings files are backed up before changes.

## Why two git hooks

The two gates land in different hooks because each needs something only it
can see:

- `pre-commit` runs before the message exists — so the diff scan lives
  there (`hooks/pre-commit-gate.sh` -> `check_diff.py --staged`): the code
  must be clean.
- `commit-msg` receives the message file as `$1` — so the log-before-fix
  AREA gate lives there: the fix must be logged.

Together: the code is clean, and the error it fixes is logged.
