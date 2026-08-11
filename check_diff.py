"""check_diff.py — Agent Diff Gate: AI-code quality gate for git diffs.

Sits between the AI coding agent and `git commit`. Reads a git diff and flags
the churn / vulnerability patterns AI-generated code tends to produce:

  R1 hardcoded-secrets       tokens / keys / credentials in added lines
  R2 silent-failure          swallowed exceptions (except: pass, empty catch)
  R3 missing-error-handling  open()/int()/json.loads() outside try/with (Python)
  R4 duplicate-logic         identical statements added repeatedly (copy-paste)
  R5 ignores-existing        redefines a symbol that already exists in the file

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

import argparse
import fnmatch
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


def _clean_path(p: str) -> str:
    """Normalize a diff path: strip a/ b/ prefixes, quotes, and /dev/null."""
    p = p.strip().strip('"').strip("'")
    if p == "/dev/null":
        return ""
    for pref in ("a/", "b/"):
        if p.startswith(pref):
            return p[len(pref):]
    return p


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

RULES = {
    "R1": R1_NAME,
    "R2": R2_NAME,
    "R3": R3_NAME,
    "R4": R4_NAME,
    "R5": R5_NAME,
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

DEFAULT_SUGGEST = {
    R1_NAME: "load secrets from environment / a secret store; never commit tokens",
    R2_NAME: "let the error surface (log + re-raise) or handle it; do not swallow it",
    R3_NAME: "wrap in try/except (FileNotFoundError/OSError/ValueError) or use with",
    R4_NAME: "extract the repeated statement into one shared helper and call it",
    R5_NAME: "reuse the existing symbol instead of redefining it",
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


def rule_hardcoded_secrets(f: DiffFile) -> list[tuple]:
    out = []
    for ln in f.added:
        for msg, sugg in _secret_matches(ln.text):
            out.append(("HIGH", "R1", f.path, ln.lineno, msg, sugg))
    return out


def rule_silent_failure(f: DiffFile) -> list[tuple]:
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


def rule_missing_error_handling(f: DiffFile) -> list[tuple]:
    if not f.path.endswith(".py"):
        return []
    out = []
    for run in f.added_runs:
        try_seen = False
        for ln in run:
            t = ln.text
            if re.search(r"\btry\s*:", t):
                try_seen = True
            # the try block is over: later lines are unguarded again.
            # \b (not \s*:) so BOTH bare 'except:' and typed 'except OSError:'
            # close the scope (logged: R3 try-scope reset misses typed handlers)
            if re.match(r"^\s*(except|finally)\b", t):
                try_seen = False
            if OPEN_RE.search(t) and "with" not in t and not try_seen:
                out.append((
                    "MEDIUM", "R3", f.path, ln.lineno,
                    "open() called outside try/with — missing file-error handling",
                    "use 'with open(...)' and catch FileNotFoundError/OSError",
                ))
            if JSON_LOADS_RE.search(t) and not try_seen:
                out.append((
                    "MEDIUM", "R3", f.path, ln.lineno,
                    "json.loads() without a try — JSONDecodeError can crash",
                    "wrap in try/except json.JSONDecodeError",
                ))
            if CONV_RE.search(t) and not try_seen:
                out.append((
                    "MEDIUM", "R3", f.path, ln.lineno,
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


def rule_duplicate_logic(f: DiffFile) -> list[tuple]:
    counts: dict[str, list[int]] = {}
    for ln in f.added:
        if _substantive(ln.text):
            counts.setdefault(ln.text.strip(), []).append(ln.lineno)
    out = []
    for text, lines in counts.items():
        if len(lines) >= 2:
            out.append((
                "MEDIUM", "R4", f.path, lines[0],
                f"identical statement added {len(lines)}x (copy-paste signal): "
                f"{text[:48]!r}",
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
    # signal 1: names still present on disk (not on added lines)
    existing = _existing_names(root / f.path, added_lines)
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
            "name": RULES.get(self.rule, self.rule),
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "suggestion": self.suggestion,
        }


def analyze(
    diff_text: str,
    *,
    root: Path,
    rule_filter: set[str] | None = None,
    excludes: list[str] | None = None,
    max_findings: int = 100,
) -> list[Finding]:
    """Run all enabled rules over the diff; return capped, deduped findings."""
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
        for sev, rule, file, line, msg, sugg in rule_hardcoded_secrets(f):
            add(sev, rule, file, line, msg, sugg)
        for sev, rule, file, line, msg, sugg in rule_silent_failure(f):
            add(sev, rule, file, line, msg, sugg)
        for sev, rule, file, line, msg, sugg in rule_missing_error_handling(f):
            add(sev, rule, file, line, msg, sugg)
        for sev, rule, file, line, msg, sugg in rule_duplicate_logic(f):
            add(sev, rule, file, line, msg, sugg)
        for sev, rule, file, line, msg, sugg in rule_ignores_existing(f, root):
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
        lines.append(f"[{f.severity}] {f.rule} {RULES.get(f.rule, '')}  {f.file}:{f.line}")
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
            ["git", *args, "--no-color"], capture_output=True, text=True, timeout=60
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
    path.write_text(_insert_entry(text, entry), encoding="utf-8", newline="\n")
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
    path.write_text(new_text, encoding="utf-8", newline="\n")
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
    rules_path.write_text(rules, encoding="utf-8", newline="\n")
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
    rule_filter: set[str] | None = None
    if args.rule:
        rule_filter = set()
        for chunk in args.rule:
            for r in chunk.split(","):
                r = r.strip().upper()
                if r not in RULES:
                    print(f"unknown rule '{r}' (known: {', '.join(RULES)})")
                    return 2
                rule_filter.add(r)

    fail_on = "none" if args.warn_only else args.fail_on

    if args.file:
        try:
            diff_text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"--file: cannot read {args.file}: {exc}")
            return 2
        source = f"file ({args.file})"
    elif args.stdin:
        diff_text = sys.stdin.read()
        source = "stdin"
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

    files = parse_diff(diff_text)
    changed = len(files)
    excluded = 0
    if args.exclude:
        excluded = sum(
            1 for f in files if any(fnmatch.fnmatch(f.path, pat) for pat in args.exclude)
        )

    findings = analyze(
        diff_text, root=HERE,
        rule_filter=rule_filter, excludes=args.exclude,
        max_findings=args.max_findings,
    )
    passes, _ = gate_verdict(findings, fail_on)

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
            "exit": 0 if passes else 1,
        }
        print(json.dumps(payload, indent=2))
        return 0 if passes else 1

    print(format_human(findings, source, fail_on,
                       analyzed=changed - excluded, changed=changed))
    return 0 if passes else 1


if __name__ == "__main__":
    sys.exit(main())
