# Agent Diff Gate

[![CI](https://github.com/vartiainen1/agent-diff-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/vartiainen1/agent-diff-gate/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Release](https://img.shields.io/github/v/release/vartiainen1/agent-diff-gate)
![Dependencies: zero](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)

**The pre-commit quality gate for AI-generated code.** A zero-dependency,
stdlib-only CLI that sits between your AI coding agent and `git commit`,
scans the diff, and flags the churn / vulnerability patterns AI-generated
code tends to produce — **before** the code reaches a pull request.

`v0.2.0` · MIT · Python 3.9+ · **zero dependencies** · fully offline — nothing
leaves your machine.

---

## Live demo

The gate refuses a bad diff — and lets a clean one straight through. Both
animations are **real output** from the same tiny demo repo, before and
after the classic AI-agent mistakes (a leaked API key, swallowed
exceptions, SQL built from strings) were fixed:

| Failing scan | Passing scan |
|---|---|
| ![Agent Diff Gate catching a leaked API key, swallowed exceptions, and a SQL-injection risk](assets/demo.gif) | ![Agent Diff Gate passing a clean diff](assets/demo-pass.gif) |

Run it on your own diff in [Quick start](#quick-start).

---

## Why this exists

CodeRabbit, Greptile and Qodo review PRs *after* they are pushed — and they
need an LLM API, a subscription, and your code uploaded to their cloud.
Semgrep / pre-commit SAST catches syntax-level patterns but not the
*semantic* churn class AI agents produce: swallowed exceptions, unprotected
conversions, re-implemented helpers, pasted blocks, secrets in new shapes.

Agent Diff Gate is **local, free, offline, and deterministic** — a single
stdlib Python file (~77 KB, ~1,820 lines — the whole thing fits in one code
review) you can drop into any repo, with no network and no data leaving the
machine.

Dogfood, not theory: the gate reviews its own diffs. The round that added
`--allow-host` produced **15 findings on this codebase — including a docs
claim the implementation didn't satisfy** — and every one was fixed or
documented, none suppressed.

## Highlights

- **14 built-in rules** — secrets, silent failures, missing error handling,
  duplicate logic, ignored existing patterns, and 10 more (see below), plus
  an **external plugin system** (`rules.d/`) so new rules never have to grow
  the core file. The rules are 14 `rule_*` functions (~1,340 of the ~1,820
  lines); the core infrastructure — parser, gate, log tooling, plugin
  loader — is a lean ~480.
- **Every diff source**: working tree, staged index, commit range, stdin, or
  a saved diff file — pre-commit, pre-push, or in CI.
- **Severity gate with real exit codes** — wire it into any script or hook:
  `0` pass, `1` findings at/above your threshold, `2` usage error.
- **Comment/docstring aware** — rules that scan code skip strings and
  comments, so test fixtures and prose never produce noise.
- **Hardened for untrusted input** — path containment, secret redaction,
  control-character stripping, an 8 MiB input cap, and a no-traceback
  boundary guard (see [Security](#security)).
- **Measured performance** — linear scan: ~0.5 s per 10k diff lines
  (200-file benchmark, interpreter startup included), ~1.4 s at 30k —
  fast enough to run on every commit without slowing anyone down.

## The fourteen built-in rules

| Rule | Pattern | Severity |
|------|---------|----------|
| R1 `hardcoded-secrets` | GitHub tokens, `sk-` API keys, AWS keys, private keys, credential literals | HIGH |
| R2 `silent-failure` | `except: pass`, empty handlers, bare except, empty `catch {}` | HIGH |
| R3 `missing-error-handling` | `open()` / `int()` / `json.loads()` outside try/with (Python) | MEDIUM |
| R4 `duplicate-logic` | identical statements added repeatedly (copy-paste) | MEDIUM |
| R5 `ignores-existing` | redefines a symbol already in the file | MEDIUM |
| R6 `hardcoded-url` | `http(s)://` endpoints baked into code (comments / placeholder hosts ignored) | LOW |
| R7 `missing-input-validation` | `int(input(...))` / `parseInt(req.query…)` without a guard | MEDIUM |
| R8 `dangerous-eval-exec` | `eval()` / `exec()` / `compile()` / `new Function` / `shell=True` | MEDIUM |
| R9 `missing-path-validation` | `Path(input(...))` / `open(req…)` — path from user input (Python) | MEDIUM |
| R10 `broad-exception` | `except Exception` / `except BaseException` with a real body | MEDIUM |
| R11 `todo-marker` | `TODO` / `FIXME` / `XXX` / `HACK` markers in added lines | LOW |
| R12 `hardcoded-config-credentials` | connection strings with embedded creds, hardcoded JWTs | HIGH |
| R13 `unsafe-deserialization` | `pickle.load(s)` / `yaml.load` / PHP `unserialize` (HIGH), XML parsers (MEDIUM) | HIGH |
| R14 `sql-injection` | SQL built from f-strings, template literals, `.format()` or concatenation | HIGH |

Every finding reports `file:line`, the rule, a plain-language message, and a
concrete suggestion. Full semantics for each rule live in
[Rules detail](#rules-detail).

## Quick start

```sh
# Install (or just copy check_diff.py into your repo — it's one file, ~77 KB, zero deps)
pip install agent-diff-gate
diff-gate --help

# Gate your staged changes right now
diff-gate --staged
```

Single-file drop-in (no install at all):

```sh
cp check_diff.py /path/to/your/repo/
python /path/to/your/repo/check_diff.py --staged
```

Run it on every commit with the provided hooks (see
[Hooks & agent integration](#hooks--agent-integration)).

## Usage — the full CLI

### 1. Pick a diff source (exactly one)

| Flag | Reads |
|------|-------|
| *(none)* | the working tree (`git diff`) |
| `--staged` | the index (`git diff --cached`) — the classic pre-commit mode |
| `--range A B` | the commit range `A..B` |
| `--stdin` | a unified diff piped in |
| `--file PATH` | a saved diff file |

### 2. Tune the gate

| Flag | Effect |
|------|--------|
| `--fail-on SEV` | fail when a finding is at least this severity: `high` (default) / `medium` / `low` / `none` |
| `--warn-only` | report findings but never fail (equivalent to `--fail-on none`) |
| `--max-findings N` | cap findings reported (default 100; `0` = unlimited) |
| `--rule R1,R3` | run only the listed rules (repeatable, comma-separated) |
| `--exclude GLOB` | skip files matching a glob (repeatable, e.g. `*.lock` `vendor/*`) |
| `--allow-host HOST` | extra R6 URL allow-list host (repeatable, comma-separated; subdomains of an allowed host are covered). Same as the `AGENT_DIFF_GATE_HOSTS` env var (comma/space separated) |
| `--json` | machine-readable output (one JSON document: `gate` + `findings[]`) |
| `--list-rules` | list every built-in and plugin rule, then exit |
| `--rules-dir PATH` | load plugin rules from `PATH` instead of the default `rules.d/` |
| `--version` | print the version and exit |

### 3. Error-log tooling (this repo's log-before-fix discipline)

| Flag | Effect |
|------|--------|
| `--log [PATH]` | validate the error log (default `errors.txt`) |
| `--add --area A --error E --cause C [--status S]` | scaffold a new log entry |
| `--has-entry AREA` | exit 0 only if `AREA` is already logged (gates a fix) |
| `--check-commit MSG` | re-run the gate on a commit-message file |
| `--archive-days N [--apply]` | preview/apply archiving of old FIXED entries |
| `--lessons [--apply]` | distill CAUSE lines into `rules.txt` section 7 |
| `--logfile PATH` | point log-tooling at a different file |

**Exit codes:** `0` gate passes · `1` findings at/above the `--fail-on`
threshold · `2` usage / environment error.

### Example output

Actual output from scanning a demo repo that repeats three classic
AI-agent mistakes (a leaked API key, swallowed exceptions, SQL built from
strings):

```text
=== AGENT DIFF GATE — scan report ===
source   : git diff HEAD~1 HEAD
files    : 1 changed, 1 analyzed
findings : 6 (3 HIGH, 3 MEDIUM)

[HIGH] R1 hardcoded-secrets  app.py:11
  API key (sk-...) in an added line
  suggestion: found API key (sk-...); load secrets from environment / a secret store; never commit tokens

[MEDIUM] R2 silent-failure  app.py:15
  bare except catches every exception type
  suggestion: catch specific exceptions (ValueError, OSError, ...) explicitly

[HIGH] R2 silent-failure  app.py:16
  exception handler whose only body is pass/continue
  suggestion: let the error surface (log + re-raise) or handle it; do not swallow it

[MEDIUM] R3 missing-error-handling  app.py:18
  int()/float() on a variable without a guard — ValueError risk
  suggestion: validate the input or wrap in try/except ValueError

[MEDIUM] R7 missing-input-validation  app.py:18
  int()/float() applied directly to input() - unvalidated user input can raise ValueError
  suggestion: validate the input first and handle conversion errors (try/except ValueError, Number.isNaN)

[HIGH] R14 sql-injection  app.py:9
  string concatenation inside an SQL call - injection risk
  suggestion: use parameterized queries or prepared statements instead of building SQL from strings

GATE: FAIL — fail-on 'high', 6 finding(s)
```

With `--json`, the same scan is one document:

```json
{"gate": "FAIL", "fail_on": "high",
 "findings": [{"rule": "R1", "file": "src/auth.py", "line": 12,
               "severity": "HIGH", "message": "...", "suggestion": "..."}]}
```

## Hooks & agent integration

**Git hooks — hard enforcement for humans and agents alike:**

```sh
cp hooks/pre-commit-gate.sh .git/hooks/pre-commit      # blocks commits with findings
cp hooks/git-commitmsg-hook.sh .git/hooks/commit-msg   # log-before-fix AREA gate
chmod +x .git/hooks/pre-commit .git/hooks/commit-msg
```

`./hooks/install.sh --git` installs both for you.

**Claude Code / Cursor starter kit** — the repo ships a copy-into-any-project
kit in `templates/` (see `templates/README.md`, or start with the blog-style walkthrough in [`templates/adoption-guide.md`](templates/adoption-guide.md)):

| Piece | Copy to | Purpose |
|---|---|---|
| `CLAUDE.md` | repo root | Claude Code reads it every session |
| `claude-settings.json` | `.claude/settings.json` | Claude Code runs the gate on every commit tool call |
| `cursor-gate.mdc` | `.cursor/rules/gate.mdc` | Cursor always-on rule |
| `hooks/block-no-verify-hook.sh` | `hooks/` | blocks `git commit --no-verify` bypasses |

**CI backstop:** the `commit-gate` job in `.github/workflows/ci.yml`
re-checks every pushed commit server-side, where `--no-verify` cannot reach.

## Plugin rules (rules.d/)

New rules no longer have to grow `check_diff.py`. Drop a module into
`rules.d/` declaring `RULE_ID` / `RULE_NAME` / `SEVERITY` / `DESCRIPTION`
(plus optional `SUGGESTION`) and a `rule_diff(f)` function, and it runs
alongside the built-ins on every scan. Plugin rules respect `--rule`
filtering, dedup, `--max-findings` and the severity gate like any built-in.
A broken plugin is skipped with a warning — it never crashes the gate.

```bash
python check_diff.py --list-rules              # built-ins + plugins
python check_diff.py --rules-dir /path/to/dir  # load rules from elsewhere
```

See `rules.d/_example_rule.py` (working template) and `rules.d/README.md`
(the plugin contract).

## Security

The gate analyzes **untrusted input** (hostile diffs, third-party plugins),
so it is hardened where it counts:

- **Path containment** — diff-controlled paths are resolved and verified
  inside the repo root; `..`, absolute paths, NUL bytes and escaping
  symlinks are refused.
- **No secret leakage** — credential-shaped strings are redacted from
  findings before they reach the terminal or `--json`.
- **No terminal injection** — control/bidi characters are stripped from
  diff-derived text.
- **Bounded input** — stdin/file reads are capped at 8 MiB (exit 2).
- **No tracebacks in hooks** — a boundary guard turns unexpected errors
  into a clean `GATE: internal error` message.
- **Trust model** — plugins execute code: only add rules you trust. Diffs
  are untrusted data. The tool is fully offline.

Full details: [`SECURITY.md`](SECURITY.md). To report a vulnerability,
follow the private-advisory path documented there — never a public issue.

## Limits

- **Heuristic linter, not a SAST scanner** — it can miss real
  vulnerabilities and can report false positives. Treat findings as review
  aids, not proof of security.
- Scans diffs up to **8 MiB**; the gate is deterministic and offline.

## Tests

`python _test_diff.py` — **170 tests** covering the diff parser, all
fourteen built-in rules + plugins (happy + negative + edge), the severity
gate model, the error-log tooling, and process-style output-value
integration tests. `all 170 should pass`. The suite runs on
**Python 3.9 / 3.11 / 3.12 across Ubuntu and Windows** in CI, plus a
packaging job that builds the wheel and smoke-tests the `diff-gate` console
script.

## Rules detail

### R1 — hardcoded secrets (HIGH)
Detects `ghp_…` GitHub tokens, `sk-…` API keys, `AKIA…` AWS access keys,
`-----BEGIN … PRIVATE KEY-----` blocks, and credential assignments like
`password = "…"` / `api_key = "…"` / `client_secret: "…"`. Placeholder
values (`your_password_here`, `example`, `changeme`) are not flagged.
`os.environ[...]` / function calls are not flagged.

### R2 — silent failure (HIGH / MEDIUM)
`except: pass`, `except Exception: pass`, empty multi-line handlers whose
only body is `pass`/`continue`, and empty `catch {}` blocks in JS/TS/Java/C#
silently swallow errors — the number-one churn source in AI-generated code.
Bare `except:` (catches everything) is reported as MEDIUM.

### R3 — missing error handling (MEDIUM, Python)
`open()` outside `with`/`try`, `int()`/`float()` on a variable without a
guard, and `json.loads()` without a try. The try-scope is tracked
statement-by-statement, so calls after `except`/`finally` are flagged again.

### R4 — duplicate logic (MEDIUM)
Identical non-trivial statements added 2+ times in one diff — the copy-paste
signal that means "extract a helper". Scans code files only, with the same
comment/docstring stripping as R3/R7/R9/R10 — test-fixture strings, comments,
and log/docs/config boilerplate never fire.

### R5 — ignores existing patterns (MEDIUM)
An added `def`/`class`/`function`/`const` whose name already exists in the
file's unchanged lines — the AI re-implemented something that was already
there. Removed+added same-name pairs are treated as legitimate replacements,
not duplicates.

### R6 — hardcoded URLs (LOW)
`http(s)://` endpoints committed in added lines — the URL the code will
talk to becomes impossible to change without a code change. Comment and
docstring lines, plus placeholder hosts (`localhost`, `127.0.0.1`,
`example.com`, docs sites), are ignored. Teams with legitimate internal
endpoints extend the allow-list at runtime with `--allow-host` or the
`AGENT_DIFF_GATE_HOSTS` env var — subdomains of an allowed host are covered,
host values are normalized (scheme/port/path/case stripped) — so no one has
to fork the file. R6 flags all non-placeholder URLs in added lines, including
test files. If your test fixtures use real endpoints, add `--exclude '*_test*'`
or add the host to `--allow-host` — the escape hatch is explicit, never hidden.

### R7 — missing input validation (MEDIUM)
`int(input(...))` / `float(input(...))` (Python) and `parseInt(req.query…)`
/ `Number(req.body…)` (JS) convert raw user/request input without a guard.
Conversions inside try/except are considered validated and not flagged.

### R8 — dangerous eval/exec (MEDIUM)
`eval()` / `exec()` / `compile()` (Python), `new Function(...)` (JS) and
`subprocess.run(..., shell=True)` execute strings as code — arbitrary-code /
command-injection risk. Member access (`re.compile`, `pattern.exec`) is not
flagged.

### R9 — missing path validation (MEDIUM, Python)
`Path(...)` / `open(...)` fed directly from user-controlled input
(`input()`, `sys.argv`, `os.environ`, `request`/`req`/`body` access, or a
variable named like user input) — a path-traversal vector. Fixed paths like
`Path(CONFIG_DIR) / "app.json"` are not flagged.

### R10 — broad exception handlers (MEDIUM)
`except Exception:` / `except BaseException:` that actually handle the error
instead of re-raising a specific type — every error type gets masked. The
swallow-shapes (`except Exception: pass` / lone `pass` body) are left to R2.
A broad catch-all that returns a default instead of re-raising — e.g. a
handler that swallows the error and returns `None` — is still flagged
(MEDIUM): it looks handled but masks every error type. The boundary — R2
covers handlers that do nothing, R10 covers broad catches that handle by
doing something generic instead of re-raising a specific type.

### R11 — TODO/FIXME markers (LOW)
`TODO` / `FIXME` / `XXX` / `HACK` markers left in added lines — the diff
contains unfinished work that should be tracked, not committed silently.
Only the annotation shape counts (`TODO:` / `FIXME:` / `XXX:` / `HACK:` /
`TODO(user):` owner tags, or a bare marker at end-of-line) — prose that merely
*mentions* the markers is not flagged. Unlike R3/R7/R9/R10, this rule
deliberately still scans comments and docstrings: marker annotations live
there. That means an annotation such as `TODO: tune before release` written
in a YAML or JSON-with-comments config file is flagged by design —
unfinished configuration is still unfinished work.

### R12 — hardcoded config credentials (HIGH)
Connection strings with embedded credentials (`postgres://user:pass@…`,
`mysql://…`, `mongodb://…`, `jdbc:…`) and hardcoded JWT tokens — secrets in
shapes R1 does not cover. `sqlite:///` local files and env lookups are not
flagged.

### R13 — unsafe deserialization (HIGH / MEDIUM)
`pickle.load/loads`, `yaml.load` (unsafe by default) and PHP `unserialize`
can execute arbitrary code on untrusted input (HIGH). XML parsers
(`xml.etree`, `lxml.etree`, `minidom`, `xml.sax`) without external-entity
protection are an XXE risk (MEDIUM). `yaml.safe_load` / `json.loads` stay
clean.

### R14 — SQL injection (HIGH)
SQL statements built from strings — `execute(f"…{var}…")`, JS query
template literals with `${…}`, `.format()` on a query, or `+` concatenation
inside an `execute`/`query` call. Parameterized queries (`%s` + param
tuple, prepared statements) are not flagged.

## Error-log discipline (this repo)

This repo uses the **agent error-log system**: every error encountered is
logged in `errors.txt` BEFORE it is fixed (enforced by
`git-commitmsg-hook.sh`). Session notes live in `notes.txt`, distilled
lessons in `rules.txt`. Run `python start.py` at the start of a session.

## Companion tools

The gate is the **enforcement layer** of the agent-memory family. It embeds
its own error-log discipline (above) so a team can adopt it standalone; for
cross-project memory, pair it with the siblings:

- **agent-error-log** — reactive memory: what BROKE and how it was fixed
- **agent-decision-log** — proactive memory: what was CHOSEN and why
- **agent-log-ai** — reasoning layer: why it kept happening
- **agent-diff-gate** (this repo) — enforcement layer: catch it before commit

## Contributing & license

- **License:** MIT — see [`LICENSE`](LICENSE).
- **Changes:** [`CHANGELOG.md`](CHANGELOG.md) (Keep a Changelog / SemVer).
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **Security:** [`SECURITY.md`](SECURITY.md).
