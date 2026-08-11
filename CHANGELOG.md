# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`check_diff.py` — the Agent Diff Gate.** A zero-dependency, stdlib-only
  CLI that analyzes git diffs for the churn / vulnerability patterns
  AI-generated code tends to produce, before the code reaches a PR.
- **Diff sources:** working tree (`git diff`), staged (`--staged`), commit
  range (`--range A B`), stdin (`--stdin`), or a saved diff file (`--file`).
- **Fourteen rules:**
  - R1 `hardcoded-secrets` (HIGH) — GitHub tokens, `sk-` API keys, AWS keys,
    private keys, credential literals (placeholders and env lookups ignored).
  - R2 `silent-failure` (HIGH/MEDIUM) — `except: pass`, empty handlers, bare
    except, empty `catch {}`.
  - R3 `missing-error-handling` (MEDIUM, Python) — `open()`/`int()`/
    `json.loads()` outside try/with, with statement-level try-scope tracking.
  - R4 `duplicate-logic` (MEDIUM) — identical statements added 2+ times.
  - R5 `ignores-existing` (MEDIUM) — redefines a symbol already in the file
    (diff-context aware, works offline).
  - R6 `hardcoded-url` (LOW) — `http(s)://` endpoints baked into added
    lines; comments and placeholder/docs hosts ignored.
  - R7 `missing-input-validation` (MEDIUM) — `int(input(...))` /
    `parseInt(req.query…)` converting raw input without a guard (try-aware).
  - R8 `dangerous-eval-exec` (MEDIUM) — `eval()`/`exec()`/`compile()`,
    `new Function(...)`, `subprocess` with `shell=True`.
  - R9 `missing-path-validation` (MEDIUM, Python) — `Path()`/`open()` from
    user-controlled input (`input()`, `sys.argv`, request access).
  - R10 `broad-exception` (MEDIUM) — `except Exception`/`BaseException`
    handlers; swallow-shapes stay R2's terrain.
  - R11 `todo-marker` (LOW) — `TODO`/`FIXME`/`XXX`/`HACK` markers in added
    lines.
  - R12 `hardcoded-config-credentials` (HIGH) — connection strings with
    embedded creds, hardcoded JWTs.
  - R13 `unsafe-deserialization` (HIGH/MEDIUM) — `pickle`/`yaml.load`/
    `unserialize`; XML parsers (XXE).
  - R14 `sql-injection` (HIGH) — SQL built from f-strings, template
    literals, `.format()` or concatenation.
- **Plugin interface:** external rules in `rules.d/` — a module declares
  `RULE_ID`/`RULE_NAME`/`SEVERITY`/`DESCRIPTION` (+ optional `SUGGESTION`)
  and a `rule_diff(f)` function. `--list-rules` lists built-ins + plugins;
  `--rules-dir PATH` loads from elsewhere. Broken plugins are skipped with
  a warning — they never crash the gate.
- **Gate model:** `--fail-on high|medium|low|none`, `--warn-only`,
  `--rule R1,R2`, `--exclude GLOB`, `--max-findings N`, `--json` output.
  Exit codes: 0 pass / 1 findings / 2 usage error.
- **Error-log tooling** (agent-error-log family discipline): `--add`,
  `--has-entry`, `--check-commit`, `--archive-days N [--apply]`,
  `--lessons [--apply]`, `--log [PATH]`, `--logfile PATH` override.
- **Full repo kit:** commit-msg hook, `hooks/install.sh` blockers,
  CI (tests + linter + drift guard + commit gate), release + publish
  workflows, README with drift-guarded test count, AGENTS.md, SECURITY,
  CONTRIBUTING, Code of Conduct, MIT license.
- **Tests:** `_test_diff.py` — 118 tests including process-style
  output-value integration tests. all 118 should pass.

### Fixed (dogfood, logged in errors.txt before fixing)

- R3 try-scope never reset after an except block — later unprotected calls
  were missed.
- R5 ignored the diff's own context lines in `--file`/`--stdin` mode.
- R3 scope reset missed typed except handlers (`except OSError:`).

## [0.0.0] — placeholder (never released)

- Repository scaffolding only.
