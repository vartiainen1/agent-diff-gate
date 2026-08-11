#!/bin/sh
# hooks/pre-commit-gate.sh — the diff-scan half of the Agent Diff Gate.
#
# Runs check_diff.py --staged and aborts the commit when the gate fails.
# Together with git-commitmsg-hook.sh (the log-before-fix AREA gate):
#   1. pre-commit  -> the staged code is clean
#   2. commit-msg  -> the error being fixed is logged
#
# Install:
#   cp hooks/pre-commit-gate.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
#   (or: ./hooks/install.sh --git  installs BOTH hooks)
#
# CONFIG (all optional env vars):
#   PYTHON                 — interpreter (default: python3/python/py, first
#                            that actually runs)
#   AGENT_DIFF_GATE_DIR    — folder containing check_diff.py when it is NOT
#                            at the repo root (default: repo root)
#   AGENT_DIFF_GATE_ARGS   — extra args, e.g. "--fail-on medium" or
#                            "--exclude *_test*" (unquoted) for test-heavy
#                            repos; globbing is disabled, so no quoting needed
#   AGENT_DIFF_GATE_OFF    — set to 1 to deliberately bypass this hook
#                            (an escape hatch; see hooks/README.md)
set -u

[ "${AGENT_DIFF_GATE_OFF:-}" = "1" ] && exit 0

# nothing staged -> nothing to gate
if git diff --cached --quiet; then
    exit 0
fi

# find a python that actually RUNS (respect PYTHON override; probe each
# candidate - the Windows Store 'python3' stub exists but cannot run)
PY=""
for cand in ${PYTHON:-python3 python py}; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import sys" >/dev/null 2>&1; then
        PY="$cand"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "pre-commit-gate: no working python found (set PYTHON)" >&2
    exit 1
fi

# check_diff.py lives at the repo root by default (git rev-parse works both
# from .git/hooks/ and from an agent-hook invocation in the project dir)
GATE_DIR="${AGENT_DIFF_GATE_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || true)}"
if [ -z "$GATE_DIR" ] || [ ! -f "$GATE_DIR/check_diff.py" ]; then
    echo "pre-commit-gate: check_diff.py not found at repo root (set AGENT_DIFF_GATE_DIR)" >&2
    exit 1
fi

# disable globbing so an unquoted AGENT_DIFF_GATE_ARGS value like
# '--exclude *_test*' is passed to the gate literally (reviewer)
set -f
report="$(mktemp 2>/dev/null || echo /tmp/agent-diff-gate-report.txt)"
"$PY" "$GATE_DIR/check_diff.py" --staged ${AGENT_DIFF_GATE_ARGS:-} >"$report" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "GATE BLOCKED — fix the findings below, stage the fixes, then commit again:"
    cat "$report"
    rm -f "$report"
    exit 1
fi
rm -f "$report"
exit 0
