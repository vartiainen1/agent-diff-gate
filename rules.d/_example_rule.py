"""_example_rule.py — template for external rules.

The leading underscore means the loader skips this file. Copy it to a new
name (e.g. `no_print.py`) to activate the rule — then check_diff.py picks
it up automatically and `--list-rules` shows it.

A plugin is a plain Python module declaring metadata plus a rule_diff(f)
function. It runs alongside the built-in rules R1..R14. A broken plugin is
skipped with a warning — it never crashes the gate. Finding tuples are
normalized: the rule id always becomes RULE_ID, invalid severities fall
back to SEVERITY, empty suggestions to SUGGESTION, and malformed findings
are dropped.

    RULE_ID       required, unique (R15, R16, ... or P1, P2, ...)
    RULE_NAME     required, kebab-case, shown in reports
    SEVERITY      required: HIGH | MEDIUM | LOW (default for findings)
    DESCRIPTION   required, one line for --list-rules
    SUGGESTION    optional; used when a finding carries no suggestion
    rule_diff(f)  required: DiffFile -> list of 6-tuples
"""

RULE_ID = "R15"
RULE_NAME = "example-rule"
SEVERITY = "MEDIUM"
DESCRIPTION = "flags added lines that call example() — template rule"
SUGGESTION = "do not call example(); use the documented API instead"


def rule_diff(f):
    """f is a DiffFile: f.path (str) and f.added (AddedLine with .lineno/.text).

    Return a list of 6-tuples:
        (severity, rule_id, path, line_number, message, suggestion)
    A severity outside HIGH/MEDIUM/LOW falls back to the module's SEVERITY;
    an empty suggestion falls back to SUGGESTION.
    """
    out = []
    for ln in f.added:
        if "example()" in ln.text:
            out.append((
                SEVERITY, RULE_ID, f.path, ln.lineno,
                "example() called in an added line",
                SUGGESTION,
            ))
    return out
