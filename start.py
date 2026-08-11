"""start.py — Agent session bootstrap.

Run at the start of every working session to start calibrated:
    python start.py          (Windows: double-click start.bat)

Prints, from the folder holding this script:
  0. an error-log health check (runs check_diff.py --log),
  1. the reading order (rules -> errors -> notes),
  2. the mandatory rules (check before coding, log before fixing),
  3. the current non-FIXED entries in the error log
     (OPEN / PARTIAL / MITIGATED / WORKAROUND),
  4. the latest session note from the notes file.

Stdlib only.
"""

import sys
from datetime import datetime
from pathlib import Path

try:
    import check_diff  # sibling tool: validates the error log
except ImportError:
    check_diff = None

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
RULES_FILE = "rules.txt"
ERRORS_FILE = "errors.txt"
NOTES_FILE = "notes.txt"

BAR = "=" * 80
SUB = "-" * 80


def load(name):
    p = HERE / name
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8", errors="replace")


def active_errors(text):
    """Return [(header, status)] for error-log entries not marked FIXED."""
    if check_diff is None:
        return None
    out = []
    for e in check_diff.parse_entries(text):
        status = e["fields"].get("STATUS", "?").strip()
        if status.rstrip(".") == "FIXED":
            continue
        out.append((f"[{e['tag']}] AREA: {e['area']}", status))
    return out


def last_session_note(text):
    lines = text.splitlines()
    heads = [i for i, l in enumerate(lines) if l.startswith("SESSION NOTE")]
    if not heads:
        return "(no session notes found in the notes file)"
    h = heads[-1]
    start = h - 1 if h > 0 and set(lines[h - 1].strip()) == {"="} else h
    i = h + 1
    if i < len(lines) and len(lines[i].strip()) >= 10 and set(lines[i].strip()) == {"="}:
        i += 1
    end = len(lines)
    for j in range(i, len(lines)):
        s = lines[j].strip()
        if len(s) >= 10 and set(s) == {"="}:
            end = j
            break
    return "\n".join(lines[start:end]).strip()


def main():
    errors = load(ERRORS_FILE)
    notes = load(NOTES_FILE)

    print(BAR)
    print("AGENT SESSION BOOTSTRAP")
    print(f"when       : {datetime.now():%Y-%m-%d %H:%M}")
    print(f"workspace  : {HERE}")
    print(BAR)

    print(f"\n{SUB}")
    print("STEP 0 - ERROR-LOG HEALTH CHECK (check_diff.py --log):")
    log_path = HERE / ERRORS_FILE
    if check_diff is None:
        print("  (check_diff.py not found - skipping health check)")
    elif not log_path.exists():
        print(f"  (missing file: {log_path})")
    else:
        rc, problems = check_diff.validate_log(log_path.read_text(
            encoding="utf-8", errors="replace"))
        if rc == 0:
            print("  RESULT: log healthy - safe to code.")
        else:
            print("  RESULT: PROBLEMS FOUND - fix the log before coding")
            for p in problems:
                print(f"    - {p}")

    print("\nREADING ORDER (before doing anything):")
    print(f"  1. {RULES_FILE}   -> the RULES (how to behave)")
    print(f"  2. {ERRORS_FILE}  -> check BEFORE coding/debugging")
    print(f"  3. {NOTES_FILE}   -> notes + session context")
    print("\nMANDATORY RULES:")
    print("  - CHECK BEFORE CODING: review the error log before writing code,")
    print("    so past mistakes are not repeated.")
    print("  - LOG BEFORE FIXING: found an error? log it FIRST, only then fix")
    print("    it. No exceptions.")

    print(f"\n{SUB}")
    print("ACTIVE / UNRESOLVED ERRORS (non-FIXED, from the error log):")
    if errors is None:
        print(f"  (missing file: {HERE / ERRORS_FILE})")
    else:
        aes = active_errors(errors)
        if aes is None:
            print("  (skipped - check_diff.py not found)")
        elif not aes:
            print("  (none - the error log is clean, no unresolved items)")
        else:
            for header, status in aes:
                print(f"  {header}")
                print(f"      STATUS: {status}")

    print(f"\n{SUB}")
    print(f"LATEST SESSION NOTE (from {NOTES_FILE}):")
    if notes is None:
        print(f"  (missing file: {HERE / NOTES_FILE})")
    else:
        for line in last_session_note(notes).splitlines():
            print(f"  {line}")

    print(f"\n{SUB}")
    print("Tips: keep error entries short and factual; end working sessions with")
    print(f"a dated SESSION NOTE (YYYY-MM-DD): TITLE at the end of {NOTES_FILE}.")
    print("Run 'python check_diff.py' to gate the current diff (--staged for")
    print("the index); '--log' validates the error log; '--add' scaffolds a")
    print("new entry before fixing anything.")
    print(BAR)


if __name__ == "__main__":
    main()
