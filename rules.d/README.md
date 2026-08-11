# rules.d/ — external plugin rules

New rules do not have to grow `check_diff.py`. Drop a Python module into
this folder and the gate loads it as a plugin on every run.

## Contract

A plugin is a plain module declaring metadata plus one function:

```python
RULE_ID = "R15"              # required, unique (R15, R16, ... or P1, P2, ...)
RULE_NAME = "my-rule"        # required, kebab-case, shown in reports
SEVERITY = "MEDIUM"          # required: HIGH | MEDIUM | LOW
DESCRIPTION = "one line"     # required, shown by --list-rules
SUGGESTION = "how to fix"    # optional fallback suggestion

def rule_diff(f):
    """f is a DiffFile: f.path (str), f.added (AddedLine with .lineno/.text).
    Return a list of (severity, rule_id, path, line_number, message, suggestion)."""
    ...
```

Findings outside `HIGH`/`MEDIUM`/`LOW` fall back to the module's
`SEVERITY`; empty suggestions fall back to `SUGGESTION`; the rule id in
every finding tuple is normalized to the module's `RULE_ID`. A plugin
that raises during import or during a scan is skipped with a stderr
warning — it can never crash the gate, and malformed findings are
dropped rather than reported.

## Trust

Plugin modules are executed as Python at import time and at scan time. Only
add rules you trust — they run with the same privileges as the gate itself.
A broken plugin is skipped with a warning; a malicious one is code execution
by design. Never run the gate against a repository whose `rules.d/` you did
not author.

## Rules

- Files starting with `_` are ignored (this template, helpers).
- `RULE_ID` must not collide with a built-in rule or another plugin.
- Plugin rules run after the built-ins on every scanned file; they respect
  `--rule` filtering, `--max-findings`, dedup, and the severity gate like
  any built-in rule.

## Usage

```bash
python check_diff.py --list-rules              # built-ins + plugins
python check_diff.py --rules-dir /path/to/rules   # load from elsewhere
python check_diff.py --rule R15                 # run just the plugin
```

See `_example_rule.py` for a working template — copy it to a new name and
edit.
