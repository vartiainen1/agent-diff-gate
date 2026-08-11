# Contributing

Thanks for considering a contribution. This is a small, dependency-free
project — please keep it that way.

## Ground rules

- **Stdlib only** — no new runtime dependencies unless truly unavoidable.
- **Plain and portable** — Python 3.9+, plain shell; must work on Windows,
  macOS, and Linux.
- **Small changes** — prefer minimal diffs; no gold-plating.
- **Tested** — every change to `check_diff.py` or `start.py` must keep
  `python _test_diff.py` green (all 132 should pass) and the error log
  clean (`python check_diff.py --log`).
- **Rules need negative tests** — a rule that fires on clean code is worse
  than no rule. Every rule change ships with both a positive and a negative
  test.

## Reporting bugs

Open an issue with:

- what you ran (exact commands),
- what happened (output),
- what you expected,
- your OS and Python version.

Please check `errors.txt` and existing issues first — the error log exists
so mistakes aren't reported twice.

## Submitting changes

1. Fork the repo and create a feature branch.
2. Make your change. Add or update tests in `_test_diff.py` for any
   behavior change.
3. Run the checks:
   ```sh
   python _test_diff.py        # all tests pass
   python check_diff.py --log  # error log validates
   python -m py_compile check_diff.py start.py
   sh -n git-commitmsg-hook.sh
   ```
4. Commit and open a pull request. If your change fixes an error, follow the
   project's own convention and name the logged error in the commit message:
   `git commit -m "... (AREA: <what broke>)"`.

## Style

- Follow the existing code: clear function docstrings, minimal comments,
  `pathlib`/stdlib idioms, UTF-8 everywhere.
- The README documents behavior — keep it in sync when you change behavior,
  including the test count (the CI drift guard enforces it).
