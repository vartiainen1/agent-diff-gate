"""check_diff.py — Agent Diff Gate: AI-code quality gate for git diffs.

Sits between the AI coding agent and `git commit`. Reads a git diff and flags
the churn / vulnerability patterns AI-generated code tends to produce:

  R1 hardcoded-secrets       tokens / keys / credentials in added lines
  R2 silent-failure          swallowed exceptions (except: pass, empty catch)
  R3 missing-error-handling  open()/int()/json.loads() outside try/with (Python)
  R4 duplicate-logic         identical statements added repeatedly (copy-paste)
  R5 ignores-existing        redefines a symbol that already exists in the file
  R6 hardcoded-url           http(s):// endpoints baked into code (LOW)
  R7 missing-input-validation  int(input(...)) / parseInt(req.query...) raw (MEDIUM)
  R8 dangerous-eval-exec     eval()/exec()/compile()/new Function/shell=True (MEDIUM)
  R9 missing-path-validation  Path()/open() from input/request/argv (Python, MEDIUM)
  R10 broad-exception        except Exception/BaseException catches everything (MEDIUM)
  R11 todo-marker            TODO/FIXME/XXX/HACK markers in added lines (LOW)
  R12 hardcoded-config-credentials  connection strings / JWTs with embedded creds (HIGH)
  R13 unsafe-deserialization pickle/yaml.load/unserialize/XML parsers (HIGH/MEDIUM)
  R14 sql-injection         SQL built from f-strings/template literals/concat (HIGH)
  R15+ plugins             external rules from rules.d/*.py (see --list-rules)

Stdlib only, zero dependencies, works offline. Run from a git repo:

    python check_diff.py              # analyze the working-tree diff (git diff)
    python check_diff.py --staged     # analyze the index (git diff --cached)
    python check_diff.py --range A B  # analyze a commit range A..B
    git diff | python check_diff.py --stdin

Exit codes: 0 = gate passes, 1 = findings at/above the --fail-on severity,
2 = usage / environment error.

The repo also carries the agent-error-log discipline (log before fixing):

    python check_diff.py --log                  # validate errors.txt
    python check_diff.py --add                  # scaffold a new log entry
    python check_diff.py --has-entry "AREA"     # gate a fix before applying it
    python check_diff.py --check-commit MSG     # re-run the gate on a message
    python check_diff.py --archive-days N [--apply]
    python check_diff.py --lessons [--apply]
"""

from __future__ import annotations  # PEP 563: lazy annotations -> Python 3.9 compat

import argparse
import fnmatch
import importlib.util
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
if sys.stdin and hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")

VERSION = "0.1.0"

HERE = Path(__file__).resolve().parent
LOG_FILE = "errors.txt"
RULES_FILE = "rules.txt"
PLUGIN_DIR = "rules.d"
MAX_DIFF_BYTES = 8 * 1024 * 1024  # cap on untrusted diff input (S4): the
# gate runs inside pre-commit hooks / CI and must never OOM on a huge diff


def _write_lf(path, text):
    """Write text preserving \n line endings on every platform.
    Path.write_text only gained the newline= kwarg in Python 3.10, so this
    helper keeps Python 3.9 compat (CI matrix runs 3.9)."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _check_input_cap(label: str, text: str) -> int | None:
    """Exit code 2 when text exceeds the input cap (S4), else None. One
    shared implementation so the guard cannot drift between input channels.
    The cap counts CHARACTERS (each up to 4 UTF-8 bytes - worst case ~4x
    the byte budget, 32 MiB for the 8 MiB cap): still bounded, so the gate
    can never be made to exhaust memory."""
    if len(text) > MAX_DIFF_BYTES:
        print(f"{label} exceeds {MAX_DIFF_BYTES} chars - "
              "refusing to analyze (input cap, S4).")
        return 2
    return None

# --- severity model --------------------------------------------------------
SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
SEVERITIES = ("HIGH", "MEDIUM", "LOW")

# --- error-log discipline (canonical statuses, family vocabulary) ----------
STATUSES = ("FIXED", "PARTIAL", "OPEN", "MITIGATED", "WORKAROUND")
DEFAULT_STATUS = "OPEN"
TPL_MARKER = "5) TO ADD A NEW ENTRY"
ARCHIVED_MARKER = "ARCHIVED ENTRIES"
ENTRY_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2})\] AREA: (?P<area>.+?)$(?P<body>(?:\n[ \t].*)*)",
    re.MULTILINE,
)


# ===========================================================================
# diff parsing
# ===========================================================================
class AddedLine:
    """One '+' line from the new side of the diff."""

    __slots__ = ("lineno", "text")

    def __init__(self, lineno: int, text: str):
        self.lineno = lineno
        self.text = text


class DiffFile:
    """A single changed file: path + its added lines (new-side numbering)."""

    def __init__(self, path: str):
        self.path = path
        self.old_path: str | None = None
        self.is_new = False
        self.is_deleted = False
        self.is_rename = False
        self.binary = False
        self.added: list[AddedLine] = []
        self.context: list[str] = []   # unchanged lines (the pre-change file)
        self.context_n: list[int] = []  # their new-side linenos (state tracking)
        self.removed: list[str] = []   # '-' lines (the pre-change file)

    @property
    def added_runs(self) -> list[list[AddedLine]]:
        """Split added lines into contiguous blocks (runs)."""
        runs: list[list[AddedLine]] = []
        cur: list[AddedLine] = []
        prev = None
        for ln in self.added:
            if prev is not None and ln.lineno != prev + 1 and cur:
                runs.append(cur)
                cur = []
            cur.append(ln)
            prev = ln.lineno
        if cur:
            runs.append(cur)
        return runs


CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


def _display_safe(text: str) -> str:
    """Strip terminal/bidi control characters from diff-derived text so a
    hostile diff cannot spoof or corrupt the report (ANSI escapes,
    backspaces, RTL overrides). Tabs become spaces. Kept minimal: only the
    chars that carry display-side effects (S3)."""
    return CONTROL_RE.sub("", text.replace("\t", " "))


def _repo_path(root: Path, rel: str) -> Path | None:
    """A diff path resolved safely inside root, or None if it could escape.

    f.path is untrusted input (--stdin/--file/another branch): a '..'
    segment, an absolute path (drive or root prefix), a NUL byte, or a symlink
    inside the repo pointing outside must never make the gate READ outside
    the repo. Callers treat None exactly like a missing file (S1). Residual
    limitation (documented, not portably fixable): Windows junction points
    (reparse points) are not followed by Path.resolve(), so a junction
    inside the repo whose target exists could pass the check - creating a
    junction needs local privileges, i.e. an attacker who already controls
    the machine and could just read the file directly."""
    if not rel or "\x00" in rel:
        return None
    try:
        p = Path(rel)
        if p.is_absolute() or ".." in p.parts:
            return None
        joined = root / p
        inside = joined.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return None  # unparsable or unresolvable path: treat as unavailable
    return joined if inside else None


def _clean_path(p: str) -> str:
    """Normalize a diff path: strip a/ b/ prefixes, quotes, /dev/null, and
    terminal/bidi control chars (S3: a hostile path must not corrupt the
    report)."""
    p = p.strip().strip('"').strip("'")
    if p == "/dev/null":
        return ""
    for pref in ("a/", "b/"):
        if p.startswith(pref):
            p = p[len(pref):]
            break
    return _display_safe(p)


def parse_diff(text: str) -> list[DiffFile]:
    """Parse a unified git diff into DiffFile objects (added lines only)."""
    files: list[DiffFile] = []
    cur: DiffFile | None = None
    old_n = new_n = 0
    in_hunk = False

    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("diff --git "):
            if cur is not None:
                files.append(cur)
            m = re.match(r"diff --git a/(.*?) b/(.*)$", line)
            cur = DiffFile(_clean_path(m.group(2)) if m else "")
            old_n = new_n = 0
            in_hunk = False
        elif cur is None:
            continue  # preamble before the first file header
        elif line.startswith("new file mode"):
            cur.is_new = True
        elif line.startswith("deleted file mode"):
            cur.is_deleted = True
        elif line.startswith("rename from "):
            cur.is_rename = True
            cur.old_path = _clean_path(line[len("rename from "):])
        elif line.startswith("rename to "):
            cur.path = _clean_path(line[len("rename to "):])
        elif line.startswith("Binary files "):
            cur.binary = True
        elif line.startswith("@@"):
            m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if not m:
                continue
            old_n, new_n = int(m.group(1)), int(m.group(2))
            in_hunk = True
        elif not in_hunk:
            continue  # index / similarity / mode-change headers
        elif line.startswith("+"):
            if not cur.is_deleted:
                cur.added.append(AddedLine(new_n, line[1:]))
            new_n += 1
        elif line.startswith("-"):
            if cur is not None and not cur.is_deleted:
                cur.removed.append(line[1:])
            old_n += 1
        elif line.startswith(" "):
            if cur is not None:
                cur.context.append(line[1:])
                cur.context_n.append(new_n)
            old_n += 1
            new_n += 1
        # "\\ No newline at end of file" and anything else: no counter change

    if cur is not None:
        files.append(cur)
    return [f for f in files if f.path and not f.is_deleted and not f.binary]


# ===========================================================================
# rules — each returns [(severity, rule, file, line, message, suggestion)]
# ===========================================================================
R1_NAME = "hardcoded-secrets"
R2_NAME = "silent-failure"
R3_NAME = "missing-error-handling"
R4_NAME = "duplicate-logic"
R5_NAME = "ignores-existing"
R6_NAME = "hardcoded-url"
R7_NAME = "missing-input-validation"
R8_NAME = "dangerous-eval-exec"
R9_NAME = "missing-path-validation"
R10_NAME = "broad-exception"
R11_NAME = "todo-marker"
R12_NAME = "hardcoded-config-credentials"
R13_NAME = "unsafe-deserialization"
R14_NAME = "sql-injection"

RULES = {
    "R1": R1_NAME,
    "R2": R2_NAME,
    "R3": R3_NAME,
    "R4": R4_NAME,
    "R5": R5_NAME,
    "R6": R6_NAME,
    "R7": R7_NAME,
    "R8": R8_NAME,
    "R9": R9_NAME,
    "R10": R10_NAME,
    "R11": R11_NAME,
    "R12": R12_NAME,
    "R13": R13_NAME,
    "R14": R14_NAME,
}

SECRET_PATTERNS = [
    (r"\bghp_[A-Za-z0-9]{36}\b", "GitHub personal access token"),
    (r"\bsk-[A-Za-z0-9]{20,}\b", "API key (sk-...)"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key ID"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
]
# generic credential assignment:  secret_name = 'long-value' / "long-value"
CRED_ASSIGN_RE = re.compile(
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|db_?password)\b\s*[=:]\s*[\"']([^\"']{6,})[\"']",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(
    r"(your[_-]?|example|changeme|placeholder|dummy|fake|xxx|<|\.\.\.)", re.I
)

# Python single-line swallowed exception bodies
PY_EXCEPT_PASS_RE = re.compile(r"\bexcept\s*([^:]*?)\s*:\s*(pass|\.\.\.|continue|break)\b")
# bare except (no exception type), body on following lines
BARE_EXCEPT_RE = re.compile(r"^\s*except\s*:\s*$")
# empty catch block in JS/TS/Java/C#/C++
EMPTY_CATCH_RE = re.compile(r"\bcatch\s*(\([^)]*\))?\s*\{\s*\}")
# R3 (Python): conversions / file opens without a guard
CONV_RE = re.compile(r"\b(int|float)\s*\(([^\"']\w)")  # non-literal argument
OPEN_RE = re.compile(r"\bopen\s*\(")
JSON_LOADS_RE = re.compile(r"\bjson\.loads\s*\(")
# R5: definition shapes we can name
DEF_RE = re.compile(
    r"^\s*(?:async\s+)?(?:def|function|class)\s+([A-Za-z_$][\w$]*)\s*(?:\(|:|$)"
)
VAR_FN_RE = re.compile(
    r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:function\b|\(|async\b)"
)

# R6: hardcoded URLs on added lines (placeholder / docs hosts allowed)

URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)")
URL_ALLOW_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "example.com", "example.org", "example.net",
    "www.w3.org", "json-schema.org", "schemas.xmlsoap.org", "tools.ietf.org",
    "developer.mozilla.org", "docs.python.org", "python.org",
    "github.com", "pypi.org",
    "img.shields.io", "shields.io",  # README badge hosts (R6)
    "react.dev", "reactjs.org", "nodejs.org", "keepachangelog.com", "semver.org",
}
# R7: conversion of raw user/request input without validation (Python + JS)
PY_RAW_INPUT_CONV_RE = re.compile(r"\b(int|float)\s*\(\s*input\s*\(")
JS_RAW_PARSE_RE = re.compile(
    r"\b(?:parseInt|parseFloat|Number)\s*\(\s*"
    r"(?:req|request|ctx|event)\.(?:query|params|body)\b"
)
# R8: dynamic code execution. (?<![\w.]) keeps re.compile / regex .exec()
# clean - a bare \b boundary would false-positive on member access
EVAL_EXEC_RE = re.compile(r"(?<![\w.])(?:eval|exec|compile)\s*\(")
NEW_FUNCTION_RE = re.compile(r"\bnew\s+Function\s*\(")

SUBPROCESS_CALL_RE = re.compile(
    r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\("
)
SHELL_TRUE_RE = re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(.*\bshell\s*=\s*True\b")


# R9: file paths built from user-controlled input (Python)
PATH_OF_RAW_RE = re.compile(r"\b(?:Path|open)\s*\(\s*(?:input\s*\(|sys\.argv|os\.environ)")
PATH_OF_REQ_RE = re.compile(r"\b(?:Path|open)\s*\(\s*(?:request|req|event)\.")
PATH_VAR_ARG_RE = re.compile(r"\b(?:Path|open)\s*\(\s*([A-Za-z_][\w]*)\s*\)")
# R10: catch-all exception handlers (R2 owns the swallow-shapes)
BROAD_EXCEPT_RE = re.compile(r"\bexcept\s+(?:BaseException|Exception)\b")
# R11: unfinished-work markers in added lines
# uppercase-only: lowercase todo/hack/xxx are common identifiers
TODO_MARKER_RE = re.compile(r"(?<![\x60\x27\x22])\b(?:TODO|FIXME|XXX|HACK)\b(?=:|\(|\s*$)")  # annotation shape only: MARKER:/MARKER(/bare-at-EOL; quote/backtick-wrapped mentions are data, not markers



# R12: credentials in non-secret shapes (connection strings, JWTs)
CONNSTR_RE = re.compile(
    r"\b(?:postgres|postgresql|mysql|mariadb|mssql|sqlserver|mongodb|redshift|"
    r"jdbc|amazon-redshift)\w*://[A-Za-z0-9_.-]+:[^@\s/]+@"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
# R13: unsafe deserialization
PICKLE_RE = re.compile(r"\bpickle\.(?:load|loads|Unpickler)\s*\(")
YAML_LOAD_RE = re.compile(r"\byaml\.load(?:_all)?\s*\(")
PHP_UNSERIALIZE_RE = re.compile(r"\bunserialize\s*\(")
XML_PARSER_RE = re.compile(r"\b(?:xml\.etree|lxml\.etree|xml\.dom\.minidom|xml\.sax)\b")
# R14: SQL built from strings (quotes written as hex escapes - no literal quote
# chars in the pattern source, so the fragment transport cannot mangle them)
PY_FSQL_RE = re.compile(r"\b(?:execute|executemany|raw_query)\s*\(\s*f[\x22\x27][^\x22\x27{}]*\{")
JS_SQL_TPL_RE = re.compile(r"\b(?:query|execute)\s*\(\s*`[^`]*\$\{")
SQL_FORMAT_RE = re.compile(r"\b(?:execute|executemany|raw_query)\s*\([^,)]*[\x22\x27]\.format\s*\(")
SQL_CONCAT_RE = re.compile(r"\b(?:execute|executemany|query)\s*\([^,)]*[\x22\x27]\s*\+")


DEFAULT_SUGGEST = {
    R1_NAME: "load secrets from environment / a secret store; never commit tokens",
    R2_NAME: "let the error surface (log + re-raise) or handle it; do not swallow it",
    R3_NAME: "wrap in try/except (FileNotFoundError/OSError/ValueError) or use with",
    R4_NAME: "extract the repeated statement into one shared helper and call it",
    R5_NAME: "reuse the existing symbol instead of redefining it",
    R6_NAME: "move the endpoint to configuration / an environment variable",
    R7_NAME: "validate the input first and handle conversion errors (try/except ValueError, Number.isNaN)",
    R8_NAME: "avoid executing strings as code; prefer ast.literal_eval / json.loads / a parser, or sanitize strictly",
    R9_NAME: "validate the path against an allowlist base directory and reject traversal (../)",
    R10_NAME: "catch specific exceptions (ValueError, OSError, ...) and re-raise or log",
    R11_NAME: "finish the work or track it in an issue; do not commit markers",
    R12_NAME: "move connection strings / tokens to environment or a secret store",
    R13_NAME: "avoid pickle/yaml.load/unserialize on untrusted data; use yaml.safe_load / json / defusedxml",
    R14_NAME: "use parameterized queries or prepared statements instead of building SQL from strings",
}

# --- rule registry: id -> metadata (built-ins; load_plugins() extends it) ---
RULE_INFO: dict[str, dict] = {
    "R1": {"name": R1_NAME, "severity": "HIGH", "description": "tokens / keys / credentials in added lines", "suggestion": DEFAULT_SUGGEST[R1_NAME]},
    "R2": {"name": R2_NAME, "severity": "HIGH", "description": "swallowed exceptions (except: pass, empty catch)", "suggestion": DEFAULT_SUGGEST[R2_NAME]},
    "R3": {"name": R3_NAME, "severity": "MEDIUM", "description": "open()/int()/json.loads() outside try/with (Python)", "suggestion": DEFAULT_SUGGEST[R3_NAME]},
    "R4": {"name": R4_NAME, "severity": "MEDIUM", "description": "identical statements added repeatedly (copy-paste)", "suggestion": DEFAULT_SUGGEST[R4_NAME]},
    "R5": {"name": R5_NAME, "severity": "MEDIUM", "description": "redefines a symbol that already exists in the file", "suggestion": DEFAULT_SUGGEST[R5_NAME]},
    "R6": {"name": R6_NAME, "severity": "LOW", "description": "http(s):// endpoints baked into code", "suggestion": DEFAULT_SUGGEST[R6_NAME]},
    "R7": {"name": R7_NAME, "severity": "MEDIUM", "description": "int(input(...)) / parseInt(req.query...) raw conversions", "suggestion": DEFAULT_SUGGEST[R7_NAME]},
    "R8": {"name": R8_NAME, "severity": "MEDIUM", "description": "eval()/exec()/compile()/new Function/shell=True", "suggestion": DEFAULT_SUGGEST[R8_NAME]},
    "R9": {"name": R9_NAME, "severity": "MEDIUM", "description": "Path()/open() from input/request/argv (Python)", "suggestion": DEFAULT_SUGGEST[R9_NAME]},
    "R10": {"name": R10_NAME, "severity": "MEDIUM", "description": "except Exception/BaseException catches everything", "suggestion": DEFAULT_SUGGEST[R10_NAME]},
    "R11": {"name": R11_NAME, "severity": "LOW", "description": "TODO/FIXME/XXX/HACK markers in added lines", "suggestion": DEFAULT_SUGGEST[R11_NAME]},
    "R12": {"name": R12_NAME, "severity": "HIGH", "description": "connection strings / JWTs with embedded creds", "suggestion": DEFAULT_SUGGEST[R12_NAME]},
    "R13": {"name": R13_NAME, "severity": "HIGH", "description": "pickle/yaml.load/unserialize/XML parsers", "suggestion": DEFAULT_SUGGEST[R13_NAME]},
    "R14": {"name": R14_NAME, "severity": "HIGH", "description": "SQL built from f-strings/template literals/concat", "suggestion": DEFAULT_SUGGEST[R14_NAME]},
}


def _secret_matches(line: str):
    """Yield (rule, message) for every secret pattern matched in one line.

    A line already matched by a specific token pattern does not also emit
    the generic credential-assignment finding (reviewer: double findings on
    one line are noise)."""
    found_token = False
    for pat, what in SECRET_PATTERNS:
        if re.search(pat, line):
            found_token = True
            yield f"{what} in an added line", f"found {what}; {DEFAULT_SUGGEST[R1_NAME]}"
    m = CRED_ASSIGN_RE.search(line)
    if m and not PLACEHOLDER_RE.search(m.group(1)) and not found_token:
        yield (
            "hardcoded credential assigned a literal value",
            f"credential '{m.group(1)[:24]}...' is a literal; {DEFAULT_SUGGEST[R1_NAME]}",
        )


def rule_hardcoded_secrets(f: DiffFile, root: Path) -> list[tuple]:
    out = []
    for ln in f.added:
        for msg, sugg in _secret_matches(ln.text):
            out.append(("HIGH", "R1", f.path, ln.lineno, msg, sugg))
    return out


def rule_silent_failure(f: DiffFile, root: Path) -> list[tuple]:
    out = []
    for run in f.added_runs:
        prev = None
        for ln in run:
            t = ln.text
            if PY_EXCEPT_PASS_RE.search(t):
                out.append((
                    "HIGH", "R2", f.path, ln.lineno,
                    "exception handler swallows the error (pass/continue/break)",
                    DEFAULT_SUGGEST[R2_NAME],
                ))
            elif EMPTY_CATCH_RE.search(t):
                out.append((
                    "HIGH", "R2", f.path, ln.lineno,
                    "empty catch block silently swallows the exception",
                    DEFAULT_SUGGEST[R2_NAME],
                ))
            elif BARE_EXCEPT_RE.match(t):
                out.append((
                    "MEDIUM", "R2", f.path, ln.lineno,
                    "bare except catches every exception type",
                    "catch specific exceptions (ValueError, OSError, ...) explicitly",
                ))
            # multi-line shape:  except X:  followed by a lone pass/...
            if prev is not None and re.match(r"^\s*except\b.*:\s*$", prev.text) \
                    and re.match(r"^\s*(pass|\.\.\.|continue)\s*$", t):
                out.append((
                    "HIGH", "R2", f.path, ln.lineno,
                    "exception handler whose only body is pass/continue",
                    DEFAULT_SUGGEST[R2_NAME],
                ))
            prev = ln
    return out


def _new_side_lines(f: DiffFile) -> list[tuple[int, str, bool]]:
    """(lineno, text, is_added) for the new-side file, in order.

    Context lines carry no lineno on their own, so the parser records them
    in ``context_n`` (new-side numbering, kept in sync with ``context``).
    Merging the two ascending lists yields the exact new-side stream, which
    lets rules track state (docstrings, try-scope) across unchanged lines
    instead of resetting at each added-run boundary.
    """
    merged = [(f.context_n[i], f.context[i], False)
              for i in range(len(f.context))]
    merged += [(ln.lineno, ln.text, True) for ln in f.added]
    merged.sort(key=lambda t: t[0])
    return merged


def _docstring_state_before(f: DiffFile, root: Path,
                            lines: list[tuple[int, str, bool]]) -> str | None:
    """Docstring opener in effect just before the first diff line.

    A docstring can open *before* the first hunk (the module docstring), so
    the diff alone cannot know that rows added inside it are prose (dogfood:
    ecfab7f added the R9/R10/R11 rows mid-docstring). When the real file is
    available — git modes, and stdin scans that run inside a repo — walk its
    lines up to the first diff line and return the opener in effect. Returns
    None for new files (their opener is added inside the diff) or when the
    file is not readable; the walk then starts with no state, as before.

    Caveat: the seed reads the *current* file, so scanning a diff whose
    new-side version differs from the working tree (e.g. an old ``--range``)
    can seed a wrong state; a file shorter than the prelude returns None
    rather than guessing from a mismatched file.
    """
    if f.is_new or root is None:
        return None
    if not lines or lines[0][0] <= 1:
        return None
    path = _repo_path(root, f.path)
    if path is None or not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    prelude = text.splitlines()[: lines[0][0] - 1]
    if len(prelude) < lines[0][0] - 1:
        return None  # file does not cover the prelude: do not guess
    in_doc = None
    for ln in prelude:
        _, in_doc = _code_only(ln, in_doc)
    return in_doc


def rule_missing_error_handling(f: DiffFile, root: Path) -> list[tuple]:
    if not f.path.endswith(".py"):
        return []
    out = []
    # walk the whole new-side file (context AND added) so a docstring or
    # try: opened by an unchanged line still guards the added rows inside
    # it; the file-backed seed covers openers that predate the first hunk
    # (dogfood: ecfab7f added the R9/R10/R11 rows mid-docstring)
    lines = _new_side_lines(f)
    try_seen = False
    in_doc = _docstring_state_before(f, root, lines)
    for lineno, text, is_added in lines:
        code, in_doc = _code_only(text, in_doc)
        if not code.strip():
            continue
        if re.search(r"\btry\s*:", code):
            try_seen = True
        # the try block is over: later lines are unguarded again.
        # \b (not \s*:) so BOTH bare 'except:' and typed 'except OSError:'
        # close the scope (logged: R3 try-scope reset misses typed handlers)
        if re.match(r"^\s*(except|finally)\b", code):
            try_seen = False
        if not is_added:
            continue
        if OPEN_RE.search(code) and "with" not in code and not try_seen:
            out.append((
                "MEDIUM", "R3", f.path, lineno,
                "open() called outside try/with — missing file-error handling",
                "use 'with open(...)' and catch FileNotFoundError/OSError",
            ))
        if JSON_LOADS_RE.search(code) and not try_seen:
            out.append((
                "MEDIUM", "R3", f.path, lineno,
                "json.loads() without a try — JSONDecodeError can crash",
                "wrap in try/except json.JSONDecodeError",
            ))
        if CONV_RE.search(code) and not try_seen:
            out.append((
                "MEDIUM", "R3", f.path, lineno,
                "int()/float() on a variable without a guard — ValueError risk",
                "validate the input or wrap in try/except ValueError",
            ))
    return out

def _substantive(text: str) -> bool:
    t = text.strip()
    if len(t) < 12:
        return False
    if t.startswith(("#", "//", "/*", "*", "import ", "from ", "}", "{", ");")):
        return False
    return True


R4_CODE_EXTS = {
    "py", "js", "mjs", "cjs", "jsx", "ts", "tsx",
    "java", "kt", "kts", "scala", "c", "h", "cpp", "hpp", "cc",
    "cs", "go", "rs", "rb", "php", "swift", "sh", "bash", "zsh",
    "sql",
}
# extension-less build/config files are code too - and Dockerfiles are a
# prime AI-churn surface (copy-pasted RUN layers)
R4_CODE_NAMES = {
    "Dockerfile", "Makefile", "Rakefile", "Gemfile", "Vagrantfile",
    "Jenkinsfile", "CMakeLists.txt", ".gitlab-ci.yml",
}


def rule_duplicate_logic(f: DiffFile, root: Path) -> list[tuple]:
    """R4: identical non-trivial statements added 2+ times in one diff = the
    copy-paste signal that means 'extract a helper'.

    Scans code files only (extension + known-filename filter) and walks the
    whole new-side file through _code_only() with the file-backed opener
    seed (mirror of R3/R7/R9/R10): duplicate string content inside
    triple-quoted strings (test fixtures AND legit templates) and comment
    mentions never fire - string content is data, not statements - while
    real code duplicates still do. Log/config/docs boilerplate (STATUS:
    labels, separators, README rows, YAML/JSON scaffolding) is excluded by
    the filter - a label or a row is not a code statement.
    """
    ext = f.path.rsplit(".", 1)[-1].lower() if "." in f.path else ""
    base = f.path.rsplit("/", 1)[-1]
    if ext not in R4_CODE_EXTS and base not in R4_CODE_NAMES:
        return []
    counts: dict[str, list[int]] = {}
    lines = _new_side_lines(f)
    in_doc = _docstring_state_before(f, root, lines)
    for lineno, text, is_added in lines:
        code, in_doc = _code_only(text, in_doc)
        if not is_added:
            continue
        if _substantive(code):
            counts.setdefault(code.strip(), []).append(lineno)
    out = []
    for text, where in counts.items():
        if len(where) >= 2:
            snippet = _display_safe(text[:48])
            if any(_secret_matches(text)):
                snippet = "<redacted: contains a credential>"  # S2
            out.append((
                "MEDIUM", "R4", f.path, where[0],
                f"identical statement added {len(where)}x (copy-paste signal): "
                f"{snippet!r}",
                DEFAULT_SUGGEST[R4_NAME],
            ))
    return out


def _existing_names(path: Path, added_lines: set[int]) -> set[str]:
    """Names defined in a file, excluding definitions on added lines."""
    names: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return names
    for i, line in enumerate(lines, start=1):
        if i in added_lines:
            continue
        m = DEF_RE.match(line)
        if m:
            names.add(m.group(1))
            continue
        m = VAR_FN_RE.match(line)
        if m:
            names.add(m.group(1))
    return names


def _names_from_lines(lines) -> set[str]:
    """Names defined in raw diff lines (context/removed) — works offline."""
    names: set[str] = set()
    for line in lines:
        m = DEF_RE.match(line)
        if m:
            names.add(m.group(1))
            continue
        m = VAR_FN_RE.match(line)
        if m:
            names.add(m.group(1))
    return names


def rule_ignores_existing(f: DiffFile, root: Path) -> list[tuple]:
    if f.is_new:
        return []
    out = []
    added_lines = {ln.lineno for ln in f.added}
    # signal 1: names still present on disk (not on added lines). The path
    # is diff-controlled, so it must pass containment or be skipped (S1).
    rp = _repo_path(root, f.path)
    existing = _existing_names(rp, added_lines) if rp is not None else set()
    # signal 2: names in the diff's unchanged context lines (mode-independent;
    # removed lines are excluded: a removed+added pair is a replacement, not
    # a duplicate)
    existing |= _names_from_lines(f.context)
    for ln in f.added:
        m = DEF_RE.match(ln.text)
        if not m:
            m = VAR_FN_RE.match(ln.text)
        if m and m.group(1) in existing:
            out.append((
                "MEDIUM", "R5", f.path, ln.lineno,
                f"redefines '{m.group(1)}' which already exists in this file — "
                "possible ignored existing pattern",
                DEFAULT_SUGGEST[R5_NAME],
            ))
    return out


def _looks_commented(t: str) -> bool:
    """True for lines that are clearly comments / docstrings."""
    s = t.lstrip()
    return s.startswith(("#", "//", "/*", "*", '"""', "'''"))

def _code_only(t: str, in_doc: str | None) -> tuple[str, str | None]:
    """Return (code, in_doc) with docstring content and #-comments removed.

    R3 inspects only real code: prose inside a triple-quoted string and
    comments (full-line or trailing) must not trigger findings, and must not
    corrupt the try-scope state (e.g. a '# try:' comment used to set
    try_seen). `in_doc` is the *opening delimiter* (triple-double quote or
    triple-single quote) while inside a docstring, so only a matching
    delimiter closes it: a lone triple-double quote in prose inside a
    triple-single docstring no longer ends the block. When a line opens a
    docstring, everything from the first triple quote on is treated as
    content. Only '#' preceded by whitespace (or at line start) is a
    comment, so '#' inside a string literal is preserved.

    Accepted heuristics: runtime triple-quoted string assignments are treated
    as docstrings; an opener outside the diff entirely (before the first
    hunk) is covered only when the real file is available and matches the
    scanned diff (see ``_docstring_state_before``).
    """
    if in_doc:
        # content line: skipped; an odd count of the opening delimiter closes
        return ("", None) if t.count(in_doc) % 2 else ("", in_doc)
    s = re.sub(r"(^|\s)#.*$", r"\1", t)  # real #-comment, not a string '#'
    for q in ('"""', "'''"):
        s = re.sub(re.escape(q) + r"[\s\S]*?" + re.escape(q), "", s)
        if s.count(q) % 2:
            # docstring left open: keep only code before the opening quote
            return s.split(q, 1)[0], q
    return s, None
def rule_hardcoded_url(f: DiffFile, root: Path) -> list[tuple]:
    out = []
    for ln in f.added:
        if _looks_commented(ln.text):
            continue
        for m in URL_RE.finditer(ln.text):
            host = m.group(1).lower().rstrip(".")
            if host in URL_ALLOW_HOSTS:
                continue
            out.append((
                "LOW", "R6", f.path, ln.lineno,
                f"hardcoded URL '{_display_safe(m.group(0))}' - endpoint baked into code",
                DEFAULT_SUGGEST[R6_NAME],
            ))
    return out


def rule_missing_input_validation(f: DiffFile, root: Path) -> list[tuple]:
    if not (f.path.endswith(".py")
            or f.path.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))):
        return []
    out = []
    # walk the whole new-side file (context AND added) so docstring and
    # try/catch state opened by unchanged lines still guards the added rows
    # inside them, and the file-backed seed covers openers before the first
    # hunk (mirror of R3). _code_only strips # comments and docstring
    # content; the extra // strip handles JS trailing comments; the
    # _looks_commented guard catches full-line /* and * comment lines.
    lines = _new_side_lines(f)
    # try_seen carries across the whole file (context + added).
    # Tradeoff: a try: context line whose closer is outside the diff
    # leaves the scope open for later hunks, which can hide real
    # unguarded conversions - accepted (a column-0 reset would
    # false-reset unindented JS try bodies).
    try_seen = False
    in_doc = _docstring_state_before(f, root, lines)
    for lineno, text, is_added in lines:
        code, in_doc = _code_only(text, in_doc)
        # JS uses // comments (and /* */); _code_only strips # only, so
        # strip trailing // here too (whitespace-guarded: // inside URLs
        # and strings is preserved; tradeoff: Python floor division
        # 'a // b' also drops text after // - accepted, patterns after
        # a // operator are vanishingly rare)
        code = re.sub(r"(^|\s)//.*$", r"\1", code)
        if not code.strip() or _looks_commented(code):
            continue
        if re.search(r"\btry\s*[:{]", code):
            try_seen = True
        if re.match(r"^\s*(?:except|finally|catch)\b"
                    r"|^\s*}\s*(?:catch|finally)\b", code):
            try_seen = False
        if not is_added or try_seen:
            continue
        if re.search(PY_RAW_INPUT_CONV_RE, code):
            out.append((
                "MEDIUM", "R7", f.path, lineno,
                "int()/float() applied directly to input() - "
                "unvalidated user input can raise ValueError",
                DEFAULT_SUGGEST[R7_NAME],
            ))
        elif re.search(JS_RAW_PARSE_RE, code):
            out.append((
                "MEDIUM", "R7", f.path, lineno,
                "request/query/body value parsed without validation - "
                "may be NaN / undefined",
                DEFAULT_SUGGEST[R7_NAME],
            ))
    return out

def rule_dangerous_eval_exec(f: DiffFile, root: Path) -> list[tuple]:
    out = []
    for run in f.added_runs:
        pending_sub = None  # added-line number of an open subprocess call
        for ln in run:
            t = ln.text
            # a def/function/class line declares a name, it does not call it
            if _looks_commented(t) or DEF_RE.match(t):
                continue
            if re.search(EVAL_EXEC_RE, t):
                out.append((
                    "MEDIUM", "R8", f.path, ln.lineno,
                    "eval()/exec()/compile() executes a string as code - "
                    "arbitrary-code-execution risk",
                    DEFAULT_SUGGEST[R8_NAME],
                ))
            if re.search(NEW_FUNCTION_RE, t):
                out.append((
                    "MEDIUM", "R8", f.path, ln.lineno,
                    "new Function(...) builds code from a string - "
                    "arbitrary-code-execution risk",
                    DEFAULT_SUGGEST[R8_NAME],
                ))
            # subprocess shell=True: same line, or a later line of an open call
            if re.search(SUBPROCESS_CALL_RE, t):
                if re.search(SHELL_TRUE_RE, t):
                    out.append((
                        "MEDIUM", "R8", f.path, ln.lineno,
                        "subprocess with shell=True - command-injection risk with "
                        "untrusted input",
                        DEFAULT_SUGGEST[R8_NAME],
                    ))
                elif t.count("(") > t.count(")"):
                    pending_sub = ln.lineno
            elif pending_sub is not None and re.search(r"\bshell\s*=\s*True\b", t):
                out.append((
                    "MEDIUM", "R8", f.path, pending_sub,
                    "subprocess with shell=True - command-injection risk with "
                    "untrusted input",
                    DEFAULT_SUGGEST[R8_NAME],
                ))
                pending_sub = None
            if pending_sub is not None and t.count(")") > t.count("("):
                pending_sub = None
    return out



def rule_missing_path_validation(f: DiffFile, root: Path) -> list[tuple]:
    """R9 (Python): a path built straight from user-controlled input can be a
    path-traversal vector - flag the raw sources, not every Path() call."""
    if not f.path.endswith(".py"):
        return []
    out = []
    # walk the whole new-side file through _code_only() so comments and
    # docstring content (incl. prose rows and one-line docstrings) never
    # fire, with the file-backed opener seed (mirror of R3/R7). No try
    # scope: wrapping a path in try/except does not validate it, so R9
    # has no try state to carry. Note: R3 may also fire on a bare open()
    # on the same line - different signals (missing error handling vs
    # path traversal), both useful. Tradeoff: a docstring left open by
    # the diff (closer outside the hunks) swallows later added lines -
    # the same accepted heuristic as R3/R7.
    lines = _new_side_lines(f)
    in_doc = _docstring_state_before(f, root, lines)
    for lineno, text, is_added in lines:
        code, in_doc = _code_only(text, in_doc)
        if not code.strip() or not is_added:
            continue
        hit = None
        if re.search(PATH_OF_RAW_RE, code):
            hit = "raw input (input()/sys.argv/os.environ)"
        elif re.search(PATH_OF_REQ_RE, code):
            hit = "request/query/body data"
        else:
            m = PATH_VAR_ARG_RE.search(code)
            if m and re.search(r"input", m.group(1), re.I):
                hit = "'" + _display_safe(m.group(1)) + "'"
        if hit:
            out.append((
                "MEDIUM", "R9", f.path, lineno,
                f"file path built from user-controlled input ({hit}) - "
                f"path-traversal risk",
                DEFAULT_SUGGEST[R9_NAME],
            ))
    return out

def rule_broad_exception(f: DiffFile, root: Path) -> list[tuple]:
    """R10: catch-all handlers (except Exception / BaseException). The
    swallow-shapes (pass / continue / break bodies) stay R2's HIGH terrain."""
    out = []
    # walk the whole new-side file through _code_only() so comments and
    # docstring content (incl. prose rows and one-line docstrings) never
    # fire, with the file-backed opener seed (mirror of R3/R7/R9). No try
    # state: R10 flags the handler itself, not its position. The
    # swallow-shape check looks at the immediately following line of the
    # merged stream (context or added) - that IS the handler's body start.
    lines = _new_side_lines(f)
    in_doc = _docstring_state_before(f, root, lines)
    for idx, (lineno, text, is_added) in enumerate(lines):
        code, in_doc = _code_only(text, in_doc)
        if not code.strip() or not is_added or _looks_commented(code):
            continue
        m = BROAD_EXCEPT_RE.search(code)
        if not m:
            continue
        if re.search(r":\s*(pass|\.\.\.|continue|break)\b", code[m.end():]):
            continue
        nxt = lines[idx + 1][1] if idx + 1 < len(lines) else ""
        if re.match(r"^\s*(pass|\.\.\.|continue|break)\s*$", nxt):
            continue
        out.append((
            "MEDIUM", "R10", f.path, lineno,
            "overly broad exception handler catches every Exception type",
            DEFAULT_SUGGEST[R10_NAME],
        ))
    return out

def rule_todo_markers(f: DiffFile, root: Path) -> list[tuple]:
    """R11: TODO/FIXME/XXX/HACK markers left in added lines = unfinished work.

    Deliberate exception to the R3/R7/R9/R10 comment-stripping sweep: marker
    annotations live IN comments and docstrings, so this rule intentionally
    scans added lines raw (comments + docstrings stay visible) - stripping
    them would silence its own signal. Instead TODO_MARKER_RE demands the
    annotation shape (MARKER-colon, MARKER(owner): owner tag, or a bare
    marker at end-of-line; a marker wrapped in quotes/backticks is data, not
    an annotation) so prose that merely names the markers never fires - the
    rule's own docstring, RULE_INFO strings, README/CHANGELOG rows, log
    prose (dogfood: 15 findings, none genuine).
    """
    out = []
    for ln in f.added:
        if TODO_MARKER_RE.search(ln.text):
            out.append((
                "LOW", "R11", f.path, ln.lineno,
                "TODO/FIXME marker left in an added line - unfinished work",
                DEFAULT_SUGGEST[R11_NAME],
            ))
    return out


def rule_config_credentials(f: DiffFile, root: Path) -> list[tuple]:
    """R12: connection strings / JWTs with embedded credentials - secrets in
    shapes R1 does not cover."""
    out = []
    for ln in f.added:
        if _looks_commented(ln.text):
            continue
        if re.search(CONNSTR_RE, ln.text):
            out.append((
                "HIGH", "R12", f.path, ln.lineno,
                "hardcoded connection string with embedded credentials",
                DEFAULT_SUGGEST[R12_NAME],
            ))
        if re.search(JWT_RE, ln.text):
            out.append((
                "HIGH", "R12", f.path, ln.lineno,
                "hardcoded JWT token in an added line",
                DEFAULT_SUGGEST[R12_NAME],
            ))
    return out


def rule_unsafe_deserialization(f: DiffFile, root: Path) -> list[tuple]:
    out = []
    for ln in f.added:
        if _looks_commented(ln.text):
            continue
        if re.search(PICKLE_RE, ln.text):
            out.append((
                "HIGH", "R13", f.path, ln.lineno,
                "pickle.load/loads on (possibly untrusted) data - "
                "arbitrary-code-execution risk",
                DEFAULT_SUGGEST[R13_NAME],
            ))
        if re.search(YAML_LOAD_RE, ln.text):
            out.append((
                "HIGH", "R13", f.path, ln.lineno,
                "yaml.load() is unsafe by default - arbitrary-code-execution "
                "risk on untrusted input",
                DEFAULT_SUGGEST[R13_NAME],
            ))
        if re.search(PHP_UNSERIALIZE_RE, ln.text):
            out.append((
                "HIGH", "R13", f.path, ln.lineno,
                "PHP unserialize() on untrusted data - object injection",
                DEFAULT_SUGGEST[R13_NAME],
            ))
        if re.search(XML_PARSER_RE, ln.text):
            out.append((
                "MEDIUM", "R13", f.path, ln.lineno,
                "XML parser without external-entity protection - XXE risk",
                DEFAULT_SUGGEST[R13_NAME],
            ))
    return out


def rule_sql_injection(f: DiffFile, root: Path) -> list[tuple]:
    out = []
    for ln in f.added:
        t = ln.text
        if _looks_commented(t):
            continue
        if re.search(PY_FSQL_RE, t):
            out.append((
                "HIGH", "R14", f.path, ln.lineno,
                "f-string interpolated into an SQL statement - injection risk",
                DEFAULT_SUGGEST[R14_NAME],
            ))
        if re.search(JS_SQL_TPL_RE, t):
            out.append((
                "HIGH", "R14", f.path, ln.lineno,
                "template literal interpolated into a query - injection risk",
                DEFAULT_SUGGEST[R14_NAME],
            ))
        if re.search(SQL_FORMAT_RE, t):
            out.append((
                "HIGH", "R14", f.path, ln.lineno,
                "format() used to build an SQL statement - injection risk",
                DEFAULT_SUGGEST[R14_NAME],
            ))
        if re.search(SQL_CONCAT_RE, t):
            out.append((
                "HIGH", "R14", f.path, ln.lineno,
                "string concatenation inside an SQL call - injection risk",
                DEFAULT_SUGGEST[R14_NAME],
            ))
    return out

# ===========================================================================
# plugin interface (external rules in rules.d/)
# ===========================================================================
def load_plugins(rules_dir: Path | None = None) -> tuple[dict, list[str]]:
    """Load external rules from rules.d/*.py; return (plugins, warnings).

    A plugin is a plain Python module declaring metadata plus a rule_diff(f)
    function (see rules.d/_example_rule.py). A broken plugin is skipped with
    a warning - it never crashes the gate. Plugin ids must not collide with
    built-in rules or other plugins.
    """
    plugins: dict[str, dict] = {}
    warnings: list[str] = []
    # clear plugin entries from any previous load in this process - the
    # registry must reflect only THIS run's plugins (reviewer: ghosts)
    for rid in list(RULE_INFO):
        if rid not in RULES:
            del RULE_INFO[rid]
    d = rules_dir or HERE / PLUGIN_DIR
    if not d.is_dir():
        return plugins, warnings
    for py in sorted(d.glob("*.py")):
        if py.name.startswith("_"):
            continue  # template / helper files are not rules
        mod_name = f"_diff_gate_plugin_{py.stem}"
        try:
            spec = importlib.util.spec_from_file_location(mod_name, py)
            if spec is None or spec.loader is None:
                warnings.append(f"{py.name}: cannot load (no spec) - rule skipped")
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as exc:
            warnings.append(f"{py.name}: import failed ({exc}) - rule skipped")
            continue
        rid = str(getattr(mod, "RULE_ID", "")).strip()
        name = str(getattr(mod, "RULE_NAME", "")).strip()
        sev = str(getattr(mod, "SEVERITY", "")).strip().upper()
        desc = str(getattr(mod, "DESCRIPTION", "")).strip()
        fn = getattr(mod, "rule_diff", None)
        if not rid or not name or not desc:
            warnings.append(f"{py.name}: missing RULE_ID/RULE_NAME/DESCRIPTION - rule skipped")
            continue
        if rid in RULES or rid in plugins:
            warnings.append(f"{py.name}: rule id '{rid}' already exists - rule skipped")
            continue
        if sev not in SEVERITIES:
            warnings.append(f"{py.name}: bad SEVERITY '{sev}' (HIGH/MEDIUM/LOW) - rule skipped")
            continue
        if not callable(fn):
            warnings.append(f"{py.name}: no rule_diff(f) function - rule skipped")
            continue
        plugins[rid] = {
            "id": rid, "name": name, "severity": sev, "description": desc,
            "suggestion": (str(getattr(mod, "SUGGESTION", "")).strip()
                           or DEFAULT_SUGGEST.get(name, "")),
            "func": fn, "file": py.name,
        }
        RULE_INFO[rid] = {"name": name, "severity": sev, "description": desc,
                          "suggestion": plugins[rid]["suggestion"]}
    return plugins, warnings


def print_rule_list(plugins: dict) -> None:
    """--list-rules: print every rule (built-in + plugin) with metadata."""

    def key(rid: str) -> tuple:
        tail = rid[1:]
        return (rid[:1].lower(), int(tail) if tail.isdigit() else 0, rid)

    for rid in sorted(RULE_INFO, key=key):
        info = RULE_INFO[rid]
        origin = "plugin" if rid in plugins else "builtin"
        print(f"{rid:>4}  {info['severity']:<6} {info['name']:<28} "
              f"[{origin}] {info['description']}")
    print(f"({len(RULE_INFO)} rule(s): {len(RULES)} built-in, "
          f"{len(plugins)} plugin(s))")


# ===========================================================================
# analysis + output
# ===========================================================================
class Finding:
    __slots__ = ("severity", "rule", "file", "line", "message", "suggestion")

    def __init__(self, severity, rule, file, line, message, suggestion):
        self.severity = severity
        self.rule = rule
        self.file = file
        self.line = line
        self.message = message
        self.suggestion = suggestion

    def as_dict(self):
        return {
            "rule": self.rule,
            "name": RULE_INFO.get(self.rule, {}).get("name", self.rule),
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "suggestion": self.suggestion,
        }


# every built-in rule takes (f, root); the ones that never read files simply
# ignore root. One uniform signature lets analyze() dispatch in a loop
# instead of 14 copy-pasted call blocks (which R4 itself flagged as the
# tool's own duplicate-logic finding).
BUILTIN_RULES = (
    rule_hardcoded_secrets,
    rule_silent_failure,
    rule_missing_error_handling,
    rule_duplicate_logic,
    rule_ignores_existing,
    rule_hardcoded_url,
    rule_missing_input_validation,
    rule_dangerous_eval_exec,
    rule_missing_path_validation,
    rule_broad_exception,
    rule_todo_markers,
    rule_config_credentials,
    rule_unsafe_deserialization,
    rule_sql_injection,
)


def analyze(
    diff_text: str,
    *,
    root: Path,
    rule_filter: set[str] | None = None,
    excludes: list[str] | None = None,
    plugins: dict | None = None,
    max_findings: int = 100,
) -> list[Finding]:
    """Run all enabled rules (built-in + plugin) over the diff; return
    capped, deduped findings. A broken external rule is skipped with a
    stderr warning, never allowed to crash the gate."""
    files = parse_diff(diff_text)
    findings: list[Finding] = []
    seen: set[tuple] = set()

    def add(sev, rule, file, line, msg, sugg):
        key = (rule, file, line, msg)
        if key in seen or (rule_filter is not None and rule not in rule_filter):
            return
        seen.add(key)
        findings.append(Finding(sev, rule, file, line, msg, sugg))

    for f in files:
        if excludes and any(fnmatch.fnmatch(f.path, pat) for pat in excludes):
            continue
        for rule_fn in BUILTIN_RULES:
            for sev, rule, file, line, msg, sugg in rule_fn(f, root):
                add(sev, rule, file, line, msg, sugg)
        if plugins:
            for p in plugins.values():
                try:
                    results = p["func"](f) or ()
                except Exception as exc:
                    # scan-time errors warn - a dead plugin must not be silent
                    print(f"warning: plugin rule '{p['id']}' ({p['file']}) "
                          f"raised {exc} - rule skipped", file=sys.stderr)
                    continue
                for res in results:
                    # malformed findings are skipped, never phantom: a bare
                    # string would unpack into garbage fields (reviewer)
                    if not isinstance(res, (tuple, list)) or len(res) != 6:
                        continue
                    sev, rule, file, line, msg, sugg = res
                    rule = p["id"]  # findings always carry the plugin's id
                    # coerce every field to a serializable type (S5 review:
                    # a plugin finding must never make json.dumps raise a raw
                    # traceback outside the boundary guard)
                    file = str(file)
                    try:
                        line = int(line)
                    except (TypeError, ValueError):
                        line = 0
                    msg = str(msg)
                    sugg = str(sugg)
                    if sev not in SEV_RANK:
                        sev = p["severity"]  # fall back to the declared default
                    if not sugg:
                        sugg = p["suggestion"]
                    add(sev, rule, file, line, msg, sugg)

    return findings[:max_findings] if max_findings > 0 else findings


def _severity_of(f: Finding) -> int:
    return SEV_RANK.get(f.severity, 0)


def gate_verdict(findings: list[Finding], fail_on: str) -> tuple[bool, int]:
    """(gate_passes, max_sev_rank_found). fail_on 'none' never fails."""
    threshold = SEV_RANK.get(fail_on.upper(), 0)
    if threshold == 0:
        return True, max((_severity_of(f) for f in findings), default=0)
    worst = max((_severity_of(f) for f in findings), default=0)
    return worst < threshold, worst


def format_human(findings, source: str, fail_on: str, analyzed: int, changed: int) -> str:
    lines = [
        "=== AGENT DIFF GATE — scan report ===",
        f"source   : {source}",
        f"files    : {changed} changed, {analyzed} analyzed",
        f"findings : {len(findings)} "
        f"({', '.join(f'{c} {s}' for s in ('HIGH', 'MEDIUM', 'LOW') if (c := sum(1 for x in findings if x.severity == s))) or 'none'})",
    ]
    for f in findings:
        lines.append("")
        lines.append(f"[{f.severity}] {f.rule} {RULE_INFO.get(f.rule, {}).get('name', '')}  {f.file}:{f.line}")
        lines.append(f"  {f.message}")
        lines.append(f"  suggestion: {f.suggestion}")
    passes, _ = gate_verdict(findings, fail_on)
    verdict = "PASS" if passes else "FAIL"
    lines.append("")
    lines.append(f"GATE: {verdict} — fail-on '{fail_on.lower()}', "
                 f"{len(findings)} finding(s)")
    return "\n".join(lines)


# ===========================================================================
# diff sources
# ===========================================================================
def _run_git(args: list[str]) -> tuple[str, str]:
    try:
        proc = subprocess.run(
            ["git", *args, "--no-color"], capture_output=True, text=True,
            timeout=60, encoding="utf-8", errors="replace",
        )
    except OSError as exc:
        return "", f"git not available: {exc}"
    except subprocess.TimeoutExpired:
        return "", "git timed out after 60s"
    if proc.returncode != 0:
        return "", proc.stderr.strip() or f"git {args[0]} failed (rc={proc.returncode})"
    return proc.stdout, ""


def get_diff(source: str, range_args: list[str] | None) -> tuple[str, str]:
    """Run the git diff for a source; return (diff_text, err).

    err is empty on success. The source LABEL is built by the caller, which
    already knows the exact invocation - this function must only distinguish
    success from failure (logged: git modes broke because the label was
    mistaken for an error).
    """
    if source == "range":
        out, err = _run_git(["diff", *range_args])
    elif source == "staged":
        out, err = _run_git(["diff", "--cached"])
    else:
        out, err = _run_git(["diff"])
    return out, err


# ===========================================================================
# error-log tooling (family discipline, log-before-fix)
# ===========================================================================
def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def parse_entries(text: str) -> list[dict]:
    """Parse error-log entries, stopping at the example/template/archived
    sections so EXAMPLE entries never count as real entries. Markers are
    line-anchored so body text mentioning a marker phrase is ignored."""
    cut = _active_cut(text)
    head = text[:cut]
    entries = []
    for m in ENTRY_RE.finditer(head):
        body = m.group("body")
        fields = {}
        for label in ("ERROR", "CAUSE", "FIX", "STATUS"):
            fm = re.search(rf"^\s*{label}:\s*(.+?)\s*$", body, re.MULTILINE)
            fields[label] = fm.group(1).strip() if fm else ""
        entries.append({
            "tag": m.group(1),
            "area": m.group("area").strip(),
            "fields": fields,
        })
    return entries


def validate_log(text: str, name: str = LOG_FILE) -> tuple[int, list[str]]:
    """Return (exit_code, problems) — 0 if the log is valid."""
    problems: list[str] = []
    entries = parse_entries(text)
    if not entries:
        problems.append("no entries found in the log")
    for e in entries:
        area = e["area"]
        for label in ("ERROR", "CAUSE", "FIX", "STATUS"):
            if not e["fields"].get(label):
                problems.append(f"[{e['tag']}] AREA: {area} — missing {label}:")
        status = e["fields"].get("STATUS", "").rstrip(".")
        if status and status not in STATUSES:
            problems.append(
                f"[{e['tag']}] AREA: {area} — unknown STATUS '{status}' "
                f"(canonical: {', '.join(STATUSES)})"
            )
    return (1 if problems else 0, problems)


def cmd_log(path: Path) -> int:
    text = load_text(path)
    rc, problems = validate_log(text, path.name)
    total = len(parse_entries(text))
    print(f"error log {path.name}: {total} entrie(s)")
    if rc:
        print("PROBLEMS:")
        for p in problems:
            print(f"  - {p}")
    else:
        print("RESULT: log healthy - safe to code.")
    return rc


def _active_cut(text: str) -> int:
    """Index where the parse region ends (first example/template/archived
    section HEADER). Markers are anchored to line starts (column 0) so body
    text that merely mentions a marker phrase cannot truncate the region
    (logged: unanchored search cut an entry mid-body)."""
    cut = len(text)
    for marker in (TPL_MARKER, ARCHIVED_MARKER, "EXAMPLE ENTRIES"):
        m = re.search(rf"^{re.escape(marker)}", text, re.MULTILINE)
        if m:
            cut = min(cut, m.start())
    return cut


def _insert_entry(text: str, entry: str) -> str:
    """Insert an entry into the ACTIVE section (before the first
    example/template/archived marker), else append."""
    cut = _active_cut(text)
    head = text[:cut].rstrip()
    tail = text[cut:]
    sep = "\n\n" if head else ""
    return f"{head}{sep}{entry}\n{tail}"


def cmd_add(path: Path, area: str, error: str, cause: str, status: str) -> int:
    status = (status or DEFAULT_STATUS).upper()
    if status not in STATUSES:
        print(f"invalid STATUS '{status}' (canonical: {', '.join(STATUSES)})")
        return 2
    text = load_text(path)
    entry = (
        f"[{datetime.now():%Y-%m-%d}] AREA: {area}\n"
        f"  ERROR: {error}\n"
        f"  CAUSE: {cause}\n"
        f"  FIX: \n"
        f"  STATUS: {status}.\n"
    )
    _write_lf(path, _insert_entry(text, entry))
    print(f"logged entry: AREA: {area} (STATUS: {status})")
    return 0


def cmd_has_entry(text: str, substr: str) -> int:
    needle = substr.lower()
    hits = [e for e in parse_entries(text) if needle in e["area"].lower()]
    if hits:
        print(f"--has-entry OK: \"{substr}\" is logged "
              f"({len(hits)} match(es)) — fix may land.")
        return 0
    print(f"--has-entry BLOCKED: \"{substr}\" is NOT logged.")
    print("  LOG BEFORE FIXING: add an entry first (python check_diff.py --add).")
    return 1


def cmd_archive(path: Path, days: int, apply: bool) -> int:
    text = load_text(path)
    if not text:
        print("archive: log file is empty or missing")
        return 1
    entries = parse_entries(text)
    today = datetime.now().date()
    cutoff = today - timedelta(days=days)
    to_move = []
    for e in entries:
        status = e["fields"].get("STATUS", "").rstrip(".")
        if status != "FIXED":
            continue
        try:
            d = datetime.strptime(e["tag"], "%Y-%m-%d").date()
        except ValueError:
            continue
        if d < cutoff:
            to_move.append(e)
    if not to_move:
        print(f"archive: no FIXED entries older than {days} day(s) to move.")
        return 0
    print(f"archive: {len(to_move)} FIXED entrie(s) older than {days} day(s):")
    for e in to_move:
        print(f"  [{e['tag']}] AREA: {e['area']}")
    if not apply:
        print("  (preview only — re-run with --apply to move them)")
        return 0
    # rebuild: remove the moved entries from the active section, put them
    # into the ARCHIVED block (logged: entries were duplicated, not moved)
    cut = _active_cut(text)
    head = text[:cut]
    spans = list(ENTRY_RE.finditer(head))
    drop = {(e["tag"], e["area"]) for e in to_move}
    # header = everything before the first entry (HOW TO USE, statuses,
    # section title) — must survive archiving (logged: it was dropped)
    header = head[:spans[0].start()] if spans else head
    new_parts = [header]
    prev_end = spans[0].start() if spans else cut
    for i, m in enumerate(spans):
        key = (m.group(1), m.group("area").strip())
        end = spans[i + 1].start() if i + 1 < len(spans) else cut
        if key in drop:
            prev_end = end  # skip this entry AND its trailing separator
            continue
        # include the separator gap from prev_end so blank lines survive
        new_parts.append(head[prev_end:end])
        prev_end = end
    blocks = []
    for e in to_move:
        blocks.append(
            f"[{e['tag']}] AREA: {e['area']}\n"
            f"  ERROR: {e['fields'].get('ERROR', '')}\n"
            f"  CAUSE: {e['fields'].get('CAUSE', '')}\n"
            f"  FIX: {e['fields'].get('FIX', '')}\n"
            f"  STATUS: FIXED.\n"
        )
    archive_block = (
        "================================================================================\n"
        "ARCHIVED ENTRIES (FIXED, moved by check_diff.py --archive-days)\n\n"
        + "\n".join(blocks)
        + "\n\n"
    )
    new_text = "".join(new_parts).rstrip() + "\n\n" + archive_block + text[cut:].lstrip("\n")
    _write_lf(path, new_text)
    print(f"archive: moved {len(to_move)} entrie(s) to the ARCHIVED section.")
    return 0


def extract_area(msg: str) -> str:
    """Pull the AREA:/LOG: marker out of a commit message (hook-compatible)."""
    line = ""
    for l in msg.splitlines():
        if re.search(r"\b(AREA|LOG):", l, re.IGNORECASE):
            line = l
            break
    m = re.search(r"(?:AREA|LOG):\s*(.+?)\s*$", line, re.IGNORECASE)
    if not m:
        return ""
    area = m.group(1)
    area = re.sub(r"[),.;:]+[ \t]*$", "", area).strip()
    return area


def cmd_check_commit(log_text: str, msg_path: Path) -> int:
    try:
        msg = msg_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"--check-commit: cannot read message file: {exc}")
        return 2
    area = extract_area(msg)
    if not area:
        print("--check-commit BLOCKED: no 'AREA:' marker in the commit message.")
        return 1
    return cmd_has_entry(log_text, area)


def cmd_lessons(log_path: Path, rules_path: Path, apply: bool) -> int:
    """Distill repeated CAUSE phrases into a LESSONS LEARNED section."""
    text = load_text(log_path)
    entries = parse_entries(text)
    causes = [e["fields"].get("CAUSE", "") for e in entries if e["fields"].get("CAUSE")]
    if not causes:
        print("lessons: no CAUSE lines to distill.")
        return 1
    words = re.findall(r"[a-z][a-z0-9-]{2,}", " ".join(causes).lower())
    stop = {
        "the", "and", "for", "was", "with", "that", "this", "from", "were", "have",
        "has", "not", "are", "had", "but", "its", "all", "any", "can", "out", "our",
        "when", "into", "than", "then", "them", "over", "also", "will", "would",
    }
    freq = Counter(w for w in words if w not in stop and not w.isdigit())
    top = freq.most_common(8)
    if not top:
        print("lessons: nothing to distill.")
        return 1
    lines = ["LESSONS LEARNED (distilled by check_diff.py --lessons):"]
    for word, n in top:
        lines.append(f"  - {word} ({n}x)")
    draft = "\n".join(lines)
    if not apply:
        print(draft)
        print("\n(proposal only — re-run with --apply to write into rules.txt)")
        return 0
    rules = load_text(rules_path)
    section = (
        "================================================================================\n"
        "LESSONS LEARNED (from the error log)\n\n"
        + "\n".join(lines) + "\n"
    )
    # replace any existing LESSONS section, else append
    if "LESSONS LEARNED (from the error log)" in rules:
        pre, _sep, _post = rules.partition(
            "================================================================================\n"
            "LESSONS LEARNED (from the error log)"
        )
        rules = pre.rstrip() + "\n\n" + section
    else:
        rules = rules.rstrip() + "\n\n" + section
    _write_lf(rules_path, rules)
    print(f"lessons: wrote {len(top)} lesson(s) into {rules_path.name}.")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="check_diff.py",
        description="Agent Diff Gate — AI-code quality gate for git diffs.",
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--staged", action="store_true", help="analyze git diff --cached")
    src.add_argument("--range", nargs=2, metavar=("A", "B"),
                     help="analyze git diff A B")
    src.add_argument("--stdin", action="store_true", help="read the diff from stdin")
    src.add_argument("--file", metavar="PATH", help="read the diff from a file")

    ap.add_argument("--rule", action="append", metavar="R1[,R2]",
                    help="only run these rules (repeatable, comma-separated)")
    ap.add_argument("--exclude", action="append", metavar="GLOB",
                    help="skip files matching a glob (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", metavar="SEV",
                    choices=["high", "medium", "low", "none"],
                    help="gate fails when a finding is at least this severity (default: high)")
    ap.add_argument("--warn-only", action="store_true",
                    help="report findings but never fail the gate (--fail-on none)")
    ap.add_argument("--max-findings", type=int, default=100,
                    help="cap the number of findings (default 100; 0 = unlimited)")
    ap.add_argument("--rules-dir", metavar="PATH",
                    help="load plugin rules from PATH instead of the default rules.d/")
    ap.add_argument("--list-rules", action="store_true",
                    help="list all built-in and plugin rules, then exit")
    ap.add_argument("--version", action="store_true", help="print version and exit")

    log = ap.add_argument_group("error-log tooling (log before fixing)")
    log.add_argument("--logfile", metavar="PATH",
                     help="log file for the log-tooling commands (default: errors.txt)")
    log.add_argument("--log", nargs="?", const=LOG_FILE, metavar="PATH",
                     help="validate the error log (default: errors.txt)")
    log.add_argument("--add", action="store_true", help="scaffold a new log entry")
    log.add_argument("--area", help="--add: AREA text")
    log.add_argument("--error", help="--add: ERROR text")
    log.add_argument("--cause", help="--add: CAUSE text")
    log.add_argument("--status", default=DEFAULT_STATUS, help="--add: STATUS")
    log.add_argument("--has-entry", metavar="AREA",
                     help="exit 0 only if AREA is already logged")
    log.add_argument("--archive-days", type=int, metavar="N",
                     help="archive FIXED entries older than N days (preview unless --apply)")
    log.add_argument("--apply", action="store_true",
                     help="apply the --archive-days / --lessons change")
    log.add_argument("--lessons", action="store_true",
                     help="distill CAUSE lines into rules.txt section 7")
    log.add_argument("--check-commit", metavar="MSG",
                     help="re-run the gate on a commit-message file")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        print(f"check_diff.py {VERSION}")
        return 0

    if args.list_rules:
        plugins, warnings = load_plugins(
            Path(args.rules_dir) if args.rules_dir else None)
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        print_rule_list(plugins)
        return 0

    log_path = Path(args.logfile) if args.logfile else HERE / LOG_FILE

    if args.add:
        if not args.area or not args.error or not args.cause:
            print("--add requires --area, --error and --cause")
            return 2
        return cmd_add(log_path, args.area, args.error, args.cause, args.status)

    if args.has_entry:
        return cmd_has_entry(load_text(log_path), args.has_entry)

    if args.check_commit:
        return cmd_check_commit(load_text(log_path), Path(args.check_commit))

    if args.archive_days is not None:
        return cmd_archive(log_path, args.archive_days, args.apply)

    if args.lessons:
        return cmd_lessons(log_path, HERE / RULES_FILE, args.apply)

    if args.log:
        return cmd_log(HERE / args.log if not Path(args.log).is_absolute() else Path(args.log))

    # --- the product: diff analysis -------------------------------------
    plugins, plugin_warnings = load_plugins(
        Path(args.rules_dir) if args.rules_dir else None)
    for w in plugin_warnings:
        print(f"warning: {w}", file=sys.stderr)

    rule_filter: set[str] | None = None
    if args.rule:
        rule_filter = set()
        known = set(RULES) | set(plugins)
        for chunk in args.rule:
            for r in chunk.split(","):
                r = r.strip().upper()
                if r not in known:
                    print(f"unknown rule '{r}' (known: {', '.join(sorted(known))})")
                    return 2
                rule_filter.add(r)

    fail_on = "none" if args.warn_only else args.fail_on

    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                diff_text = fh.read(MAX_DIFF_BYTES + 1)
        except OSError as exc:
            print(f"--file: cannot read {args.file}: {exc}")
            return 2
        if _check_input_cap(f"--file: {args.file}", diff_text) is not None:
            return 2
        source = f"file ({args.file})"
    elif args.stdin:
        diff_text = sys.stdin.read(MAX_DIFF_BYTES + 1)
        source = "stdin"
        if _check_input_cap("GATE: diff on stdin", diff_text) is not None:
            return 2
        if not diff_text.strip():
            print("GATE: PASS — empty diff on stdin, nothing to analyze (0 findings).")
            return 0
    elif args.range:
        diff_text, err = get_diff("range", list(args.range))
        source = f"git diff {args.range[0]} {args.range[1]}"
        if err:
            print(f"GATE: cannot read diff — {err}")
            return 2
        if not diff_text.strip():
            print("GATE: PASS — empty diff, nothing to analyze (0 findings).")
            return 0
    else:
        staged = args.staged
        diff_text, err = get_diff("staged" if staged else "worktree", None)
        source = "git diff --cached" if staged else "git diff (working tree)"
        if err:
            print(f"GATE: cannot read diff — {err}")
            return 2
        if not diff_text.strip():
            print("GATE: PASS — no changes to analyze (0 findings).")
            return 0

    # S5: a gate must never dump a raw traceback inside a pre-commit hook.
    # The except Exception below is a deliberate boundary handler (an
    # accepted R10 finding, same class as the tool's other two): an
    # unexpected failure must become a clean exit, never a traceback.
    try:
        files = parse_diff(diff_text)
        changed = len(files)
        excluded = 0
        if args.exclude:
            excluded = sum(
                1 for f in files
                if any(fnmatch.fnmatch(f.path, pat) for pat in args.exclude)
            )

        findings = analyze(
            diff_text, root=HERE,
            rule_filter=rule_filter, excludes=args.exclude, plugins=plugins,
            max_findings=args.max_findings,
        )
        passes, _ = gate_verdict(findings, fail_on)
    except Exception as exc:
        print(f"GATE: internal error - {exc}")
        return 2

    if args.json:
        payload = {
            "tool": "agent-diff-gate",
            "version": VERSION,
            "source": source,
            "changed": changed,
            "excluded": excluded,
            "findings": [f.as_dict() for f in findings],
            "gate": "PASS" if passes else "FAIL",
            "fail_on": fail_on,
            "plugins": sorted(plugins),
            "exit": 0 if passes else 1,
        }
        print(json.dumps(payload, indent=2))
        return 0 if passes else 1

    print(format_human(findings, source, fail_on,
                       analyzed=changed - excluded, changed=changed))
    return 0 if passes else 1


if __name__ == "__main__":
    sys.exit(main())
