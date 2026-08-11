# Versioning

The Agent Diff Gate versions *itself* the way it reviews code: mechanical,
explicit, no hidden judgment.

SemVer-compatible. The gate's real contract is **finding-set stability**:
same diff in → same findings out, in the same shape.

## The bump table

| Bump | Promise | Examples |
|------|---------|----------|
| **PATCH** (`0.2.1`) | Identical diff → identical finding set **and identical output format** (text, JSON, exit codes, reported line numbers) | parser fixes that don't change output; docs; performance; verified-identical refactors; error-log tooling; CI changes |
| **MINOR** (`0.3.0`) | Identical diff → a different finding set, or a new machine-readable surface | adding a rule; changing a rule's semantics / severity / scope; adding a flag; changing a default; a finding's reported location moving |
| **MAJOR** (`1.0.0`) | The machine interface breaks for existing consumers | removing or renaming a rule (breaks `--rule` and plugin configs); changing the JSON output shape; changing exit codes; removing/renaming flags; dropping a supported Python version |

## Rules of the road

- **Location moves are finding-set changes.** If a fix makes R3 report line
  11 instead of line 12 for the same diff, that is MINOR, not PATCH — the
  output changed even though no rule was added.
- **A new rule is MINOR by convention** (ruff, ESLint, and pylint all ship
  new checks as minors) but it *can* fail previously-green builds. Every
  MINOR that can change findings must open its CHANGELOG entry with the bold
  **Finding-set change:** label — the warning signal for upgraders.
- **Pre-1.0 cadence:** under `0.x`, SemVer itself allows MINOR to break
  things. Practical cadence: bump `0.y` whenever the finding set can change;
  `0.y.z` only for finding- and output-identical fixes.
- **Plugins:** severity/scope changes in a plugin are MINOR bumps *for that
  plugin* — plugin authors version their `rules.d/*.py` independently. The
  core gate only bumps when **built-in** rules change.

## How to cut a release

1. Classify the diff since the last tag with the table above.
2. CHANGELOG.md: replace `## [Unreleased]` with `## [X.Y.Z] - <date>`.
   MINOR/MAJOR entries start with a bold **Finding-set change:** (or
   **Breaking change:**) label.
3. Bump `VERSION` in `check_diff.py` and the badge row in `README.md` — a
   test asserts `VERSION` matches the CHANGELOG's first versioned header.
4. Green: `python _test_diff.py` (170), `python _check_readme_count.py`,
   `python check_diff.py --log`, and the gate passes on the diff.
5. Push to `master` — release.yml tags `vX.Y.Z` and opens a **draft**
   release from the CHANGELOG section (CHANGELOG.md is the single source of
   truth). Nothing is public until you publish the draft.
6. Publish the draft on the Releases page — publish.yml fires on
   `published` and is gated by the `PUBLISH_TO_PYPI` repo variable, so a
   release can never accidentally ship to PyPI.
