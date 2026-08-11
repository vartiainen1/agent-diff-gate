# How to adopt the Agent Diff Gate in your repo

*The 15-minute guide to making your AI pair programmer stop committing
garbage.*

---

Your AI coding agent is great — until 2 a.m., when it ships an `except:
pass`, re-implements a helper that already existed, and bakes an API key
into a config file. Reviews catch it too late. `git log` becomes a
scrapbook of "fix: oops".

The fix isn't a better prompt. It's a **gate** that sits between the agent
and `git commit` and refuses bad diffs before they land. This guide walks
you through adopting the [Agent Diff Gate](https://github.com/vartiainen1/agent-diff-gate)
in your repo in four short steps — no dependencies, no cloud, no data
leaving your machine.

## Step 0 — Try it in 60 seconds

The whole tool is one stdlib Python file. Drop it in and see what it thinks
of your current work:

```sh
cp check_diff.py /path/to/your/repo/
cd /path/to/your/repo
python check_diff.py --staged
```

That's it. It analyzes `git diff --cached` and reports findings like:

```text
[HIGH] R1 hardcoded-secrets  src/auth.py:12
  API key (sk-...) in an added line
  suggestion: load secrets from environment / a secret store; never commit tokens

GATE: FAIL — fail-on 'high', 1 finding(s)
```

Exit codes make it script-friendly: `0` pass, `1` findings at/above your
threshold, `2` usage error. Run `python check_diff.py --list-rules` to see
everything it checks (14 built-in rules + any plugins you add).

## Step 1 — Git hooks: hard enforcement for humans *and* agents

The gate is only useful if it actually runs. Wire it into git so every
commit is checked, whether the author is a human or an agent:

```sh
cp hooks/pre-commit-gate.sh .git/hooks/pre-commit
cp hooks/git-commitmsg-hook.sh .git/hooks/commit-msg
chmod +x .git/hooks/pre-commit .git/hooks/commit-msg
```

Two hooks, two jobs:

- **`pre-commit`** runs `check_diff.py --staged` and aborts the commit on
  findings. Clean code commits normally.
- **`commit-msg`** enforces the *log-before-fix* discipline: code commits
  must carry an `AREA:` marker that matches a logged entry in `errors.txt`.
  You write down what broke *before* you fix it — so nothing gets silently
  "fixed away" and forgotten.

> **Reality check:** `git commit --no-verify` skips both hooks. That's a
> feature for humans, an exploit for agents. Step 2 closes it.

## Step 2 — Claude Code: the agent can't skip the gate

Claude Code can intercept its own `GitCommit` tool calls and run the gate
before it commits — and it will refuse to bypass it:

```sh
mkdir -p .claude hooks
cp claude-settings.json .claude/settings.json
cp CLAUDE.md .
cp hooks/pre-commit-gate.sh hooks/
cp hooks/block-no-verify-hook.sh hooks/
```

What each piece does:

- **`CLAUDE.md`** — Claude Code reads this at every session start. It
  states the gate rule, the log-before-fix flow, and the commit convention
  so the agent follows the discipline *voluntarily*.
- **`.claude/settings.json`** — makes it *mandatory*: the agent runs the
  gate before every commit tool call and shows the report on failure.
- **`hooks/block-no-verify-hook.sh`** — closes the `--no-verify` escape
  hatch by blocking Bash calls that try it.

Now the loop is closed: even an agent that tries to cheat gets the report
slapped back in its face.

## Step 3 — Cursor: voluntary, but consistent

Cursor doesn't have tool-intercepting hooks, so enforcement is the git
hooks from step 1. What you *can* do is make the agent comply voluntarily:

```sh
mkdir -p .cursor/rules
cp cursor-gate.mdc .cursor/rules/gate.mdc
```

That always-on rule keeps Cursor on the same page as Claude Code: run the
gate, log before fixing, follow the commit convention.

## Step 4 — The discipline that makes it stick

The gate alone prevents mistakes; the **error log** prevents their
recurrence. The repo keeps an `errors.txt` where every real problem is
logged *before* it's fixed — symptom, root cause, and how it was resolved:

```sh
python check_diff.py --add --area "webhook payload missing amount" \
  --error "KeyError: 'amount' on payloads without an amount field" \
  --cause "payload['amount'] raises instead of defaulting"
```

- `--has-entry "AREA"` gates a fix until the entry exists.
- `--lessons` distills repeated causes into your rules file, so the
  *team's* rules grow from *your* incidents.
- The commit-msg hook won't let a code commit through without its entry.

It sounds bureaucratic. In practice it's a five-second habit that turns
every bug into a permanent lesson instead of a 2 a.m. re-learn.

## What changes after a week

- PRs stop containing `except: pass` and unprotected `int(input(...))`
  conversions — the number-one churn sources in AI-generated code.
- No more committed tokens or connection strings in your history.
- The agent stops re-implementing helpers that already exist.
- Your `errors.txt` becomes a searchable memory of every past incident —
  and the rules file keeps growing from real causes, not vibes.

## Configuration (all optional)

| Env var | Meaning |
|---|---|
| `PYTHON` | interpreter (default `python3`, then `python`) |
| `AGENT_DIFF_GATE_DIR` | where `check_diff.py` lives, if not the repo root |
| `AGENT_DIFF_GATE_ARGS` | extra args, e.g. `--fail-on medium` or `--exclude *_test*` |
| `AGENT_DIFF_GATE_OFF=1` | deliberate, documented bypass |

One design note worth knowing: the hooks are **fail-closed**. If
`check_diff.py` isn't where the hook expects it, the hook blocks commits
until you set `AGENT_DIFF_GATE_DIR` — because a gate that can't run must
never silently pass.

## Where to go next

- Full command reference, rules detail, and security model: the repo
  [README](https://github.com/vartiainen1/agent-diff-gate)
- The plugin system (`rules.d/`) if you want project-specific rules
- `templates/README.md` for the copy-paste kit map used throughout this
  guide

*15 minutes now, or one "fix: add missing error handling" review cycle per
day forever. Your call.*
