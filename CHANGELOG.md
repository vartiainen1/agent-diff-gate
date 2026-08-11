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
- **Tests:** `_test_diff.py` — 164 tests including process-style
  output-value integration tests. all 164 should pass.

### Fixed (dogfood, logged in errors.txt before fixing)

- R3 try-scope never reset after an except block — later unprotected calls
  were missed.
- R5 ignored the diff's own context lines in `--file`/`--stdin` mode.
- R3 scope reset missed typed except handlers (`except OSError:`).
- R3 fired on comments and docstring prose (its own module docstring
  and triple-quoted test fixtures): the rule now inspects only real
  code via `_code_only()`, which strips `#` comments, one-line
  docstrings, and multi-line docstring content (state-tracked), and
  a `# try:` comment can no longer open the try scope. Accepted
  heuristics: only a matching delimiter closes a docstring block;
  `#` preceded by whitespace is a comment (so `#` inside string
  literals is preserved); runtime triple-quoted assignments are
  treated as docstrings; docstring and try-scope state now carries
  across context lines, and an opener entirely outside the diff is
  covered by a file-backed seed when the file is available.

- R3 lost docstring and try-scope state at every added-run boundary:
  rows added inside a docstring whose opener was an unchanged context
  line (or a `try:` above the run) were scanned as code. The rule now
  walks the whole new-side file - context AND added lines in order
  (the parser records new-side linenos for context lines) - so
  docstring and try-scope state crosses unchanged lines. When the
  real file is on disk, the opener is additionally seeded from the
  file's lines before the first hunk, silencing rows added
  mid-docstring even when the opener predates the diff entirely
  (dogfood: ecfab7f's R9/R10/R11 rows, 1 finding -> 0).

- R7 scanned raw added lines: docstring prose and one-line docstrings
  mentioning int(input())/parseInt(req.query...) fired, and a
  '# try:' comment opened the try scope and hid real conversions
  below it. The rule now walks the whole new-side file through
  _code_only() (comment/docstring stripping, state carried across
  context lines, file-backed opener seed - mirror of R3) plus a
  whitespace-guarded // strip for JS trailing comments and the
  _looks_commented() guard for full-line /* and * comment lines.

- R9 scanned raw added lines: docstring prose and trailing comments
  mentioning Path(input(...))/open(input(...)) fired. The rule now
  walks the whole new-side file through _code_only() with the
  file-backed opener seed (mirror of R3/R7). No try state: wrapping
  a path in try/except does not validate it, so R9 intentionally
  has none. Dogfood: full-history R9 findings 5 -> 0 (all five were
  string-literal fixture content, correctly silenced).

- R10 scanned raw added lines: docstring prose and trailing comments
  mentioning except Exception/BaseException fired (incl. its own
  module-docstring row). The rule now walks the whole new-side file
  through _code_only() with the file-backed opener seed (mirror of
  R3/R7/R9); the swallow-shape check now looks at the next *added*
  line instead of the next line of the same run, matching the file's
  real structure. Dogfood: full-history R10 12 -> 8; the 4 gone were
  docstring prose + triple-quoted fixture strings. Remaining 8 are
  real handlers in the tool's own code, RULE_INFO strings, and docs
  prose (the pre-existing docs self-trigger class).

- **R11 (todo-marker):** the marker regex now demands the annotation shape
  (`TODO:` / `FIXME:` / `XXX:` / `HACK:` / `TODO(user):` owner tags / bare
  marker at end-of-line) — prose that merely *mentions* the markers no longer
  fires. R11 stays a **deliberate exception** to the R3/R7/R9/R10
  comment-stripping sweep: marker annotations live in comments and docstrings,
  so this rule still scans added lines raw. Dogfood: 15 findings -> 2 genuine.
- **Security hardening (S1–S6):** diff-controlled paths can no longer make
  the gate read outside the repository root (`..`, absolute paths, NUL
  bytes, escaping symlinks refused); R4 redacts credential values from its
  duplicate-logic snippet; terminal/bidi control characters are stripped
  from report text; `--stdin`/`--file` input is size-capped (8 MiB); the
  product path never leaks a raw traceback (clean `GATE: internal error`,
  exit 2); SECURITY.md documents the trust model (plugins execute code,
  diffs are untrusted input).
- **R4 (duplicate-logic) precision:** now scans code files only, walking the
  new-side file through the same comment/docstring stripping as R3/R7/R9/R10 -
  test-fixture string content, comments, and log/docs/config boilerplate no
  longer fire (full-history dogfood: 228 -> 171, all remaining hits verified
  as real code statements - rule-body idioms and test-suite assertions; per-
  commit they rarely co-occur). All built-in rules now share one `(f, root)`
  signature and the analyze() dispatcher runs them in a loop, removing the
  dispatcher's own 14x duplicated call block.
## [0.0.0] — placeholder (never released)

- Repository scaffolding only.
