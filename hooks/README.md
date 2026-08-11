# Enforcement hooks — agent-diff-gate

Git hooks are **advisory**: `git commit --no-verify` skips every hook in
`.git/hooks/`. The layers below make the bypass deliberate instead of
silent, at the layers where agents actually live.

## Layers

| Layer | What it blocks | Where |
|-------|---------------|-------|
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
./hooks/install.sh --git        # just the commit-msg gate
./hooks/install.sh --status     # what's installed
```

Idempotent; existing settings files are backed up before changes.

## Why commit-msg and not pre-commit

`pre-commit` runs before the commit message exists, so the AREA marker
cannot be read there. `commit-msg` receives the message file as `$1` and
can enforce "the error must be logged before the fix lands".
