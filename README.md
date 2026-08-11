# Agent Diff Gate

**The pre-commit quality gate for AI-generated code.** A zero-dependency CLI
that sits between your AI coding agent and `git commit`, scans the diff, and
flags the churn / vulnerability patterns AI-generated code tends to produce —
**before** the code reaches a pull request.

```sh
python check_diff.py            # analyze the working-tree diff (pre-commit)
python check_diff.py --staged   # analyze the index (git diff --cached)
python check_diff.py --range main HEAD~5   # analyze a commit range
git diff | python check_diff.py --stdin    # pipe any unified diff in
```

Exit: `0` gate passes, `1` findings at/above the threshold, `2` usage error.

---

## Why this exists

CodeRabbit, Greptile and Qodo review PRs *after* they are pushed — and they
need an LLM API, a subscription, and your code uploaded to their cloud.
Semgrep / pre-commit SAST catches syntax-level patterns but not the
*semantic* churn class AI agents produce: swallowed exceptions, unprotected
conversions, re-implemented helpers, pasted blocks.

Agent Diff Gate is **local, free, offline, and deterministic** — a single
stdlib Python file you can drop into any repo, with no network and no data
leaving the machine.

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
concrete suggestion.

## Usage

```sh
# gate a diff (default: working tree)
python check_diff.py

# staged changes only
python check_diff.py --staged

# a commit range
python check_diff.py --range main HEAD~3

# from stdin or a saved diff file
git diff | python check_diff.py --stdin
python check_diff.py --file changes.diff

# tune the gate
python check_diff.py --fail-on medium    # fail on MEDIUM or worse (default: high)
python check_diff.py --warn-only         # report but never fail
python check_diff.py --rule R1,R3        # only these rules
python check_diff.py --exclude '*.lock' --exclude 'vendor/*'
python check_diff.py --json              # machine-readable output

# no diff? just the working tree state check
python check_diff.py --log               # validate errors.txt (repo discipline)
```

Example output:

```
=== AGENT DIFF GATE — scan report ===
source   : git diff (working tree)
files    : 3 changed, 3 analyzed
findings : 9 (4 HIGH, 5 MEDIUM)

[HIGH] R1 hardcoded-secrets  src/auth.py:12
  API key (sk-...) in an added line
  suggestion: load secrets from environment / a secret store; never commit tokens

...

GATE: FAIL — fail-on 'high', 9 finding(s)
```

## Install

The whole tool is one file:

```sh
cp check_diff.py /path/to/your/repo/
python /path/to/your/repo/check_diff.py --staged
```

**Git hooks** (run the gate on every commit):

```sh
cp hooks/pre-commit-gate.sh .git/hooks/pre-commit    # blocks commits with findings
cp hooks/git-commitmsg-hook.sh .git/hooks/commit-msg # log-before-fix AREA gate
chmod +x .git/hooks/pre-commit .git/hooks/commit-msg
```

`./hooks/install.sh --git` installs both for you. For the full
copy-into-any-project starter kit (CLAUDE.md, Claude Code hooks, Cursor
rules), see `templates/README.md`.

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
signal that means "extract a helper".

### R5 — ignores existing patterns (MEDIUM)
An added `def`/`class`/`function`/`const` whose name already exists in the
file's unchanged lines — the AI re-implemented something that was already
there. Removed+added same-name pairs are treated as legitimate replacements,
not duplicates.

### R6 — hardcoded URLs (LOW)
`http(s)://` endpoints committed in added lines — the URL the code will
talk to becomes impossible to change without a code change. Comment and
docstring lines, plus placeholder hosts (`localhost`, `127.0.0.1`,
`example.com`, docs sites), are ignored.

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

### R11 — TODO/FIXME markers (LOW)
`TODO` / `FIXME` / `XXX` / `HACK` markers left in added lines — the diff
contains unfinished work that should be tracked, not committed silently.
Only the annotation shape counts (`TODO:` / `FIXME:` / `XXX:` / `HACK:` /
`TODO(user):` owner tags, or a bare marker at end-of-line) — prose that merely
*mentions* the markers is not flagged. Unlike R3/R7/R9/R10, this rule
deliberately still scans comments and docstrings: marker annotations live there.

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

## Error-log discipline (this repo)

This repo uses the **agent error-log system**: every error encountered is
logged in `errors.txt` BEFORE it is fixed (enforced by `git-commitmsg-hook.sh`).
Session notes live in `notes.txt`, distilled lessons in `rules.txt`. Run
`python start.py` at the start of a session.

## Tests

`python _test_diff.py` — 151 tests covering the diff parser, all fourteen built-in rules + plugins
(happy + negative + edge), the gate model, the error-log tooling, and
process-style output-value integration tests. all 151 should pass.

## Companion tools

This repo is the third member of the agent-memory family:

- **agent-error-log** — reactive memory: what BROKE and how it was fixed
- **agent-decision-log** — proactive memory: what was CHOSEN and why
- **agent-log-ai** — reasoning: distills lessons from both logs

## License

MIT.
