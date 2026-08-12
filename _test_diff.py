"""Tests for check_diff.py — Agent Diff Gate.

Covers the diff parser, all five rules (happy + negative + edge cases), the
gate exit-code model, the error-log tooling, and process-style output-value
integration tests (rule: verify OUTPUT VALUES, not just exit codes).
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_diff as cd

HERE = Path(__file__).resolve().parent
PY = sys.executable


def run_tool_in(cwd, *args):
    """Run check_diff.py inside a given cwd (for git-backed modes)."""
    proc = subprocess.run(
        [PY, str(HERE / "check_diff.py"), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=cwd,
    )
    return proc.returncode, proc.stdout


def run_tool(*args, stdin=None):
    """Run the real check_diff.py as a subprocess; return (rc, stdout)."""
    proc = subprocess.run(
        [PY, str(HERE / "check_diff.py"), *args],
        input=stdin, capture_output=True, text=True, encoding="utf-8",
        errors="replace", cwd=HERE,
    )
    return proc.returncode, proc.stdout


# ===========================================================================
# diff parser
# ===========================================================================
SIMPLE_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 def main():
     x = 1
+    y = 2
     z = 3
     return x
"""

MULTI_DIFF = """diff --git a/a.py b/a.py
index 1111111..2222222 100644
--- a/a.py
+++ b/a.py
@@ -1,2 +1,3 @@
 a
+b
 c
diff --git a/b.js b/b.js
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/b.js
@@ -0,0 +1,2 @@
+const x = 1;
+console.log(x);
"""

RENAME_DIFF = """diff --git a/old.py b/new.py
similarity index 50%
rename from old.py
rename to new.py
index 1111111..2222222 100644
--- a/old.py
+++ b/new.py
@@ -1,3 +1,3 @@
-print("old")
 print("new")
+print("added")
"""

DELETED_DIFF = """diff --git a/gone.py b/gone.py
deleted file mode 100644
index 1111111..0000000
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-print(1)
-print(2)
"""

BINARY_DIFF = """diff --git a/img.png b/img.png
index 1111111..2222222 100644
Binary files a/img.png and b/img.png differ
"""

NO_NEWLINE_DIFF = """diff --git a/x.py b/x.py
index 1111111..2222222 100644
--- a/x.py
+++ b/x.py
@@ -1,2 +1,3 @@
 a
+b
\\ No newline at end of file
 c
"""


class TestParseDiff(unittest.TestCase):
    def test_simple(self):
        files = cd.parse_diff(SIMPLE_DIFF)
        self.assertEqual(len(files), 1)
        f = files[0]
        self.assertEqual(f.path, "app.py")
        self.assertEqual([(a.lineno, a.text) for a in f.added], [(3, "    y = 2")])

    def test_new_file_and_multiple(self):
        files = cd.parse_diff(MULTI_DIFF)
        self.assertEqual([f.path for f in files], ["a.py", "b.js"])
        self.assertTrue(files[1].is_new)

    def test_rename_uses_new_path(self):
        files = cd.parse_diff(RENAME_DIFF)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].path, "new.py")
        self.assertTrue(files[0].is_rename)
        self.assertEqual(files[0].old_path, "old.py")
        self.assertEqual(len(files[0].added), 1)

    def test_deleted_file_excluded(self):
        files = cd.parse_diff(DELETED_DIFF)
        self.assertEqual(files, [])

    def test_binary_excluded(self):
        files = cd.parse_diff(BINARY_DIFF)
        self.assertEqual(files, [])

    def test_no_newline_marker_ok(self):
        files = cd.parse_diff(NO_NEWLINE_DIFF)
        self.assertEqual(len(files), 1)
        self.assertEqual(len(files[0].added), 1)

    def test_empty_diff(self):
        self.assertEqual(cd.parse_diff(""), [])

    def test_context_and_removed_tracked(self):
        files = cd.parse_diff(RENAME_DIFF)
        self.assertIn("print(\"new\")", files[0].context)
        self.assertIn("print(\"old\")", files[0].removed)

    def test_added_runs_splits_contiguous_blocks(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,6 +1,8 @@
 a
+1
+2
 b
+3
 c
"""
        (f,) = cd.parse_diff(diff)
        runs = f.added_runs
        self.assertEqual(len(runs), 2)
        self.assertEqual([ln.lineno for ln in runs[0]], [2, 3])
        self.assertEqual([ln.lineno for ln in runs[1]], [5])


# ===========================================================================
# rules
# ===========================================================================
def findings_for(diff_text, rule=None, root=None):
    root = root or HERE
    finds = cd.analyze(diff_text, root=root,
                       rule_filter={rule} if rule else None, max_findings=0)
    return finds


def _r6_for(url: str) -> list:
    'R6 findings for a one-line diff that adds the given URL as code.'
    d = f"""diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+URL = "{url}"
"""
    return [f for f in findings_for(d, "R6") if f.rule == "R6"]


@contextlib.contextmanager
def _extra_hosts(*hosts):
    'Temporarily extend the R6 user allow-list; restores on exit.'
    saved = set(cd.EXTRA_ALLOW_HOSTS)
    cd.EXTRA_ALLOW_HOSTS.update(hosts)
    try:
        yield
    finally:
        cd.EXTRA_ALLOW_HOSTS.clear()
        cd.EXTRA_ALLOW_HOSTS.update(saved)


class TestRules(unittest.TestCase):
    # --- R1 hardcoded secrets -------------------------------------------
    def test_r1_github_token(self):
        d = """diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1,2 @@
 ok
+ghp_123456789012345678901234567890123456
"""
        finds = findings_for(d, "R1")
        self.assertTrue(any(f.rule == "R1" and f.severity == "HIGH" for f in finds))

    def test_r1_sk_key(self):
        d = """diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1,2 @@
 ok
+key = "sk-abcdefghijklmnopqrstuvwxyz123456"
"""
        finds = findings_for(d, "R1")
        self.assertTrue(any("API key" in f.message for f in finds))

    def test_r1_aws_key(self):
        d = """diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1,2 @@
 ok
+AKIAIOSFODNN7EXAMPLE
"""
        finds = findings_for(d, "R1")
        self.assertTrue(any("AWS" in f.message for f in finds))

    def test_r1_private_key(self):
        d = """diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1,2 @@
 ok
+-----BEGIN RSA PRIVATE KEY-----
"""
        finds = findings_for(d, "R1")
        self.assertTrue(any("private key" in f.message.lower() for f in finds))

    def test_r1_credential_assignment(self):
        d = """diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1,2 @@
 ok
+password = "hunter2"
"""
        finds = findings_for(d, "R1")
        self.assertTrue(any("credential" in f.message for f in finds))

    def test_r1_no_false_positive_env(self):
        d = """diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1,3 @@
 ok
+token = os.environ["TOKEN"]
+api_key = get_secret("api")
"""
        finds = findings_for(d, "R1")
        self.assertEqual([f for f in finds if f.rule == "R1"], [])

    def test_r1_placeholder_skipped(self):
        d = """diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1,2 @@
 ok
+password = "your_password_here"
"""
        finds = findings_for(d, "R1")
        self.assertEqual([f for f in finds if f.rule == "R1"], [])

    # --- R2 silent failure ----------------------------------------------
    def test_r2_except_pass_inline(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+try:
+    risky()
+except Exception: pass
"""
        finds = findings_for(d, "R2")
        self.assertTrue(any(f.severity == "HIGH" for f in finds if f.rule == "R2"))

    def test_r2_except_pass_multiline(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+try:
+    risky()
+except:
+    pass
"""
        finds = findings_for(d, "R2")
        self.assertTrue(any("only body is pass" in f.message for f in finds))

    def test_r2_bare_except_medium(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+try:
+    risky()
+except:
+    handle()
"""
        finds = findings_for(d, "R2")
        self.assertTrue(any("bare except" in f.message for f in finds))

    def test_r2_empty_catch_js(self):
        d = """diff --git a/x.js b/x.js
--- a/x.js
+++ b/x.js
@@ -1 +1,4 @@
 ok
+try {
+  risky();
+} catch (e) {}
"""
        finds = findings_for(d, "R2")
        self.assertTrue(any("empty catch" in f.message for f in finds))

    def test_r2_no_false_positive_logged_handler(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,5 @@
 ok
+try:
+    risky()
+except ValueError as e:
+    logger.error(e)
"""
        finds = findings_for(d, "R2")
        self.assertEqual([f for f in finds if f.rule == "R2"], [])

    # --- R3 missing error handling --------------------------------------
    def test_r3_bare_open(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+fh = open("data.txt")
"""
        finds = findings_for(d, "R3")
        self.assertTrue(any("open()" in f.message for f in finds))

    def test_r3_with_open_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+with open("data.txt") as fh:
+    data = fh.read()
"""
        finds = findings_for(d, "R3")
        self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_open_in_try_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+try:
+    fh = open("data.txt")
+    data = fh.read()
+except OSError:
+    data = None
"""
        finds = findings_for(d, "R3")
        self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_int_conversion_after_except_flagged(self):
        # the try scope must RESET at the except line (regression for the
        # logged bug: calls after the block were missed)
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,9 @@
 ok
+try:
+    a = fetch()
+except OSError:
+    a = 0
+port = int(port_str)
+data = json.loads(raw)
"""
        finds = findings_for(d, "R3")
        self.assertTrue(any("int()" in f.message for f in finds))
        self.assertTrue(any("json.loads" in f.message for f in finds))

    def test_r3_int_literal_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+port = int("8080")
"""
        finds = findings_for(d, "R3")
        self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_non_python_skipped(self):
        d = """diff --git a/x.js b/x.js
--- a/x.js
+++ b/x.js
@@ -1 +1,2 @@
 ok
+const f = open("data.txt");
"""
        finds = findings_for(d, "R3")
        self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_comment_lines_skipped(self):
        # full-line and trailing comments mentioning APIs are not code
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+# open(data_file) happens in helpers.py
+x = 1  # json.loads(raw) is cached upstream
+port = 1  # int("8080") was validated earlier
+'''
        finds = findings_for(d, "R3")
        self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_docstring_content_skipped(self):
        # the dogfood false positive: docstring prose mentions the APIs, and
        # prose on the opening-quote line must be skipped too
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,7 @@
 ok
+def load(fn):
+    """Open a file with open() and parse it with json.loads(); cast the
+    result with int() where possible.
+    """
+    pass
+fh = open("data.txt")
+'''
        finds = findings_for(d, "R3")
        # docstring lines (3-5) stay silent...
        self.assertEqual([f for f in finds if f.line in (3, 4, 5)], [])
        # ...but the real open() after the docstring is still caught
        self.assertTrue(any(f.line == 7 and "open()" in f.message
                            for f in finds))

    def test_r3_try_comment_no_state_corruption(self):
        # a '# try:' comment must NOT open the try scope, or real unguarded
        # calls after it would be hidden (regression: comment lines used to
        # set try_seen)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+# try: wrapped upstream in utils.py
+fh = open("data.txt")
+port = int(port_str)
+'''
        finds = findings_for(d, "R3")
        self.assertTrue(any("open()" in f.message for f in finds))
        self.assertTrue(any("int()" in f.message for f in finds))

    def test_r3_one_line_docstring_skipped(self):
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+def parse():
+    """Uses open() and json.loads() internally."""
+'''
        finds = findings_for(d, "R3")
        self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_hash_inside_string_not_masked(self):
        # a '#' inside a string literal is not a comment, so the real code
        # on the line must still be scanned (reviewer: '#'-strip masked it)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+s = "#" + open("data.txt")
+'''
        finds = findings_for(d, "R3")
        self.assertTrue(any("open()" in f.message for f in finds))

    def test_r3_single_quote_docstring_skipped(self):
        # a lone '"""' inside a "'''" docstring must NOT close the block
        # (reviewer: the close check summed both quote types)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,5 @@
 ok
+\'\'\'
+Uses open() and one """ in the prose.
+\'\'\'
+fh = open("data.txt")
+'''
        finds = findings_for(d, "R3")
        # docstring lines (2-4) stay silent...
        self.assertEqual([f for f in finds if f.line in (2, 3, 4)], [])
        # ...but the real open() after the docstring is still caught
        self.assertTrue(any(f.line == 5 and "open()" in f.message
                            for f in finds))

    def test_r3_docstring_opener_in_context_silenced(self):
        # the mid-docstring gap: the """ opener is an unchanged context line
        # and new rows are added inside the docstring — prose, not code
        # (dogfood: ecfab7f added the R9/R10/R11 rows mid-docstring)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 """
+R9 missing-path-validation: Path() and open() on user input.
+R10 risky-exception: json.loads() without a guard.
+R11 TODO markers: cast with int() before compare.
 """
'''
        finds = findings_for(d, "R3")
        self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_docstring_closed_then_real_code_flagged(self):
        # after the context-opened docstring closes (added line), real code
        # added after it is caught again — the state must not leak past the
        # closing delimiter
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,5 @@
 """
+R9 prose with open() and json.loads().
+"""
+fh = open("data.txt")
+port = int(port_str)
'''
        finds = findings_for(d, "R3")
        # prose rows inside the context-opened docstring stay silent
        self.assertEqual([f for f in finds if f.line in (2, 3)], [])
        # real code after the close is still flagged
        self.assertTrue(any(f.line == 4 and "open()" in f.message
                            for f in finds))
        self.assertTrue(any(f.line == 5 and "int()" in f.message
                            for f in finds))

    def test_r3_try_opener_in_context_suppresses_added_calls(self):
        # a try: in an unchanged context line guards added calls (mirror of
        # the docstring gap: try-scope also crossed the run boundary before)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,5 +1,7 @@
 try:
     step1()
     result = fetch()
+fh = open("data.txt")
+data = json.loads(raw)
 except OSError:
     pass
'''
        finds = findings_for(d, "R3")
        self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_except_reset_carries_into_run(self):
        # the except: reset also crosses context lines: added unguarded
        # calls after an unchanged except: are still flagged
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,5 +1,7 @@
 try:
     step1()
 except OSError:
     pass
+port = int(port_str)
+data = json.loads(raw)
 ok()
'''
        finds = findings_for(d, "R3")
        self.assertTrue(any(f.line == 5 and "int()" in f.message
                            for f in finds))
        self.assertTrue(any(f.line == 6 and "json.loads" in f.message
                            for f in finds))

    def test_r3_file_docstring_opened_before_diff_silenced(self):
        # the opener sits *outside* the diff (before the first hunk): only
        # the file on disk knows the added row is prose (dogfood: ecfab7f
        # added the R9/R10/R11 rows mid-docstring)
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "x.py"
            f.write_text('"""\n'
                         "R1 does open() on files.\n"
                         "R2 does json.loads() on payloads.\n"
                         '"""\n'
                         "def load():\n"
                         "    pass\n", encoding="utf-8")
            d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -3,4 +3,5 @@
 R1 does open() on files.
 R2 does json.loads() on payloads.
+RN does int() on raw input.
 """
 def load():
'''
            finds = findings_for(d, "R3", root=Path(tmp))
            self.assertEqual([f for f in finds if f.rule == "R3"], [])

    def test_r3_file_docstring_closed_before_diff_still_flags(self):
        # the docstring closes before the first hunk: the seed resolves to
        # None and real added code after it is still flagged (no leak)
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "x.py"
            f.write_text('"""\n'
                         "prose\n"
                         '"""\n'
                         "ok()\n", encoding="utf-8")
            d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -4,2 +4,3 @@
 ok()
+port = int(port_str)
'''
            finds = findings_for(d, "R3", root=Path(tmp))
            self.assertTrue(any(f.line == 5 and "int()" in f.message
                                for f in finds))

    # --- R4 duplicate logic ---------------------------------------------
    def test_r4_duplicate_statement(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+result = normalize(data)
+result = normalize(data)
"""
        finds = findings_for(d, "R4")
        self.assertTrue(any("2x" in f.message for f in finds))

    def test_r4_unique_statements_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+a = normalize(data)
+b = normalize(other)
"""
        finds = findings_for(d, "R4")
        self.assertEqual([f for f in finds if f.rule == "R4"], [])

    def test_r4_short_lines_ignored(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+x = 1
+x = 1
"""
        finds = findings_for(d, "R4")
        self.assertEqual([f for f in finds if f.rule == "R4"], [])

    def test_r4_docstring_fixture_content_ignored(self):
        # dogfood class: duplicates inside a triple-quoted string in the
        # ANALYZED file are string content, not code - only the real
        # duplicates after the docstring fire (mirror of R3/R7/R9/R10)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,7 @@
 ok
+    """doc prose
+    result = normalize(data)
+    result = normalize(data)
+    """
+result = normalize(data)
+result = normalize(data)
'''
        finds = findings_for(d, "R4")
        self.assertEqual([f for f in finds if f.line in (3, 4)], [])
        self.assertTrue(any(f.line == 6 and "2x" in f.message for f in finds))

    def test_r4_non_code_extension_ignored(self):
        # log/docs/config boilerplate (STATUS: labels, separators) is not a
        # code statement - R4 scans code extensions only
        d = """diff --git a/notes.txt b/notes.txt
--- a/notes.txt
+++ b/notes.txt
@@ -1 +1,3 @@
 ok
+STATUS: OPEN.
+STATUS: OPEN.
"""
        finds = findings_for(d, "R4")
        self.assertEqual([f for f in finds if f.rule == "R4"], [])

    def test_r4_js_code_still_fires(self):
        d = """diff --git a/x.js b/x.js
--- a/x.js
+++ b/x.js
@@ -1 +1,3 @@
 ok
+const result = normalize(data);
+const result = normalize(data);
"""
        finds = findings_for(d, "R4")
        self.assertTrue(any("2x" in f.message for f in finds))

    # --- R5 ignores-existing --------------------------------------------
    def test_r5_redefinition_from_context(self):
        # no file on disk (offline mode) — the diff context must carry the signal
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,3 +1,5 @@
 def connect():
     return "existing"
+def connect():
+    return "new"
"""
        finds = findings_for(d, "R5")
        self.assertTrue(any("connect" in f.message for f in finds))

    def test_r5_no_false_positive_new_symbol(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,2 +1,3 @@
 def connect():
     return "existing"
+def disconnect():
+    return True
"""
        finds = findings_for(d, "R5")
        self.assertEqual([f for f in finds if f.rule == "R5"], [])

    def test_r5_replacement_not_flagged(self):
        # removed + added same name = a replacement (legit), not a duplicate
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,3 +1,3 @@
 def connect():
-    return "existing"
+    return "new"
"""
        finds = findings_for(d, "R5")
        self.assertEqual([f for f in finds if f.rule == "R5"], [])


    # --- R6 hardcoded URLs ----------------------------------------------
    def test_r6_hardcoded_url(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+url = "https://api.stripe.com/v1/charges"
"""
        finds = findings_for(d, "R6")
        self.assertTrue(any(f.rule == "R6" and f.severity == "LOW" for f in finds))
        self.assertTrue(any("hardcoded URL" in f.message for f in finds))

    def test_r6_comment_url_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+# see https://docs.python.org/3/library/json.html
"""
        finds = findings_for(d, "R6")
        self.assertEqual([f for f in finds if f.rule == "R6"], [])

    def test_r6_placeholder_hosts_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+BASE = "http://localhost:8000"
+ping("https://example.com")
"""
    def test_r6_docs_hosts_ok(self):
        # package-homepage/docs URLs must not trip the LOW finding
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+HOME = "https://github.com/org/repo"
+page = "https://pypi.org/project/thing/"
+"""
        finds = findings_for(d, "R6")
        self.assertEqual([f for f in finds if f.rule == "R6"], [])

    def test_r6_badge_hosts_ok(self):
        # README badge URLs (shields.io) must not trip the LOW finding
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+badge = "https://img.shields.io/badge/license-MIT-blue.svg"
+api = "https://shields.io/v1"
+"""
        finds = findings_for(d, "R6")
        self.assertEqual([f for f in finds if f.rule == "R6"], [])

    def test_r6_allow_host_flag(self):
        # --allow-host suppresses R6 for that host (and its subdomains) via
        # the real CLI wiring; unrelated hosts are still flagged
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+URL = "https://api.internal.example/v1"
+STAGING = "https://staging.internal.example/v2"
+OTHER = "https://api.stripe.com/v1"
+"""
        with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(d)
            tmp = fh.name
        buf = io.StringIO()
        try:
            with _extra_hosts():
                with contextlib.redirect_stdout(buf):
                    rc = cd.main(["--file", tmp, "--json", "--max-findings", "0",
                                  "--allow-host", "internal.example"])
        finally:
            os.unlink(tmp)
        self.assertEqual(rc, 0)
        try:
            data = json.loads(buf.getvalue())
        except json.JSONDecodeError:
            self.fail("gate did not emit a JSON document")
        r6 = [f for f in data["findings"] if f["rule"] == "R6"]
        self.assertTrue(any("stripe.com" in f["message"] for f in r6))
        self.assertFalse(any("internal.example" in f["message"] for f in r6))

    def test_r6_allow_host_env_var(self):
        # AGENT_DIFF_GATE_HOSTS (comma/space separated) suppresses R6
        old = os.environ.get("AGENT_DIFF_GATE_HOSTS")
        os.environ["AGENT_DIFF_GATE_HOSTS"] = "internal.example legacy.corp"
        try:
            hits = _r6_for("https://" + "api.internal.example/v1")
        finally:
            if old is None:
                os.environ.pop("AGENT_DIFF_GATE_HOSTS", None)
            else:
                os.environ["AGENT_DIFF_GATE_HOSTS"] = old
        self.assertEqual(hits, [])

    def test_r6_allow_host_parent_domain(self):
        # allowing the parent domain covers subdomains (dot-boundary suffix),
        # but not lookalike hosts such as notcompany.com
        with _extra_hosts("company.com"):
            sub = _r6_for("https://" + "api.staging.company.com/v1")
            lookalike = _r6_for("https://" + "notcompany.com/x")
        self.assertEqual(sub, [])
        self.assertTrue(any("notcompany.com" in f.message for f in lookalike))

    def test_r6_allow_host_normalization(self):
        # scheme / port / path / trailing dot / case are stripped when a host
        # is added to the allow-list, so pasted URLs still match
        with _extra_hosts("https://" + "API.Corp.Example:8443/v1/"):
            hits = _r6_for("https://" + "api.corp.example/x")
        self.assertFalse(hits)

    def test_r6_docstring_urls_ok(self):
        # URLs inside a docstring of the analyzed file are not endpoints
        # baked into code (the documented R6 behavior); real code still is
        # the analyzed file's docstring uses triple-single-quote markers so
        # the fixture can live inside a triple-quoted block without closing
        # it - the gate then reads the analyzed docstring as data, exactly
        # like every other R6 fixture
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,6 @@
 ok
+    '''API endpoints:
+    https://api.internal.example/v1
+    https://api.stripe.com/v1
+    '''
+url = "https://api.stripe.com/v1/charges"
+"""
        r6 = [f for f in findings_for(d, "R6") if f.rule == "R6"]
        self.assertTrue(any("api.stripe.com" in f.message for f in r6))
        self.assertFalse(any("internal.example" in f.message for f in r6))

    # --- R7 missing input validation ------------------------------------
    def test_r7_int_input_python(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+port = int(input("port: "))
"""
        finds = findings_for(d, "R7")
        self.assertTrue(any(f.rule == "R7" and f.severity == "MEDIUM" for f in finds))

    def test_r7_js_request_parse(self):
        d = """diff --git a/x.js b/x.js
--- a/x.js
+++ b/x.js
@@ -1 +1,2 @@
 ok
+const page = parseInt(req.query.page, 10);
"""
        finds = findings_for(d, "R7")
        self.assertTrue(any("NaN" in f.message for f in finds))

    def test_r7_in_try_ok(self):
        # a conversion guarded by try/except is validated - no finding
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,6 @@
 ok
+try:
+    port = int(input("port: "))
+except ValueError:
+    port = 8080
"""
        finds = findings_for(d, "R7")
        self.assertEqual([f for f in finds if f.rule == "R7"], [])

    def test_r7_literal_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+port = int("8080")
"""
        finds = findings_for(d, "R7")
        self.assertEqual([f for f in finds if f.rule == "R7"], [])

    def test_r7_docstring_prose_skipped(self):
        # docstring prose mentioning the patterns is not code (mirror of R3)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,7 @@
 ok
+def read_port():
+    """Parses int(input()) from the user and float(input()) for ratios.
+    Validated upstream before use.
+    """
+    pass
+port = int(input("port: "))
'''
        finds = findings_for(d, "R7")
        # docstring lines (3-5) stay silent...
        self.assertEqual([f for f in finds if f.line in (3, 4, 5)], [])
        # ...the real raw conversion after the docstring is still caught
        self.assertTrue(any(f.line == 7 for f in finds))

    def test_r7_one_line_docstring_skipped(self):
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+    """Parses int(input("p")) directly."""
'''
        finds = findings_for(d, "R7")
        self.assertEqual([f for f in finds if f.rule == "R7"], [])

    def test_r7_try_comment_no_state_corruption(self):
        # a '# try:' comment must NOT open the try scope, or real raw
        # conversions after it would be hidden (regression: R7 scanned raw
        # text and set try_seen from comment lines)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+# try: wrapped upstream in utils.py
+port = int(input("port: "))
'''
        finds = findings_for(d, "R7")
        self.assertTrue(any(f.line == 3 for f in finds))

    def test_r7_js_comments_skipped(self):
        # // and /* */ comment lines, and trailing // comments, must not
        # fire the JS parse pattern
        d = '''diff --git a/x.js b/x.js
--- a/x.js
+++ b/x.js
@@ -1 +1,5 @@
 ok
+// parseInt(req.query.page) is validated in middleware
+/* Number(req.body.count) is clamped upstream */
+const page = parseInt(req.query.page, 10);
+const page2 = 1; // parseInt(req.query.page) validated upstream
'''
        finds = findings_for(d, "R7")
        # comment lines (2, 3, 5) stay silent...
        self.assertEqual([f for f in finds if f.line in (2, 3, 5)], [])
        # ...the real parse is still flagged
        self.assertTrue(any(f.line == 4 for f in finds))

    def test_r7_docstring_opener_in_context_silenced(self):
        # the docstring opener is an unchanged context line: added prose
        # rows inside it are not code (mirror of R3's context fix)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 """
+R7 reads int(input("port")) from the user.
+R7 casts float(input("ratio")) for the calc.
+R7 validates parseInt-style values upstream.
 """
'''
        finds = findings_for(d, "R7")
        self.assertEqual([f for f in finds if f.rule == "R7"], [])

    # --- R8 dangerous eval/exec ------------------------------------------
    def test_r8_eval(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+result = eval(user_code)
"""
        finds = findings_for(d, "R8")
        self.assertTrue(any(f.rule == "R8" and f.severity == "MEDIUM" for f in finds))

    def test_r8_exec_and_new_function(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+exec(code)
+const f = new Function("return 1");
"""
        finds = findings_for(d, "R8")
        self.assertEqual(len([f for f in finds if f.rule == "R8"]), 2)

    def test_r8_shell_true(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+subprocess.run("ls " + path, shell=True)
"""
        finds = findings_for(d, "R8")
        self.assertTrue(any("shell=True" in f.message for f in finds))

    def test_r8_re_compile_not_flagged(self):
        # member access (.compile) must stay clean - a bare \b boundary
        # would false-positive here
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+pattern = re.compile("x")
"""
        finds = findings_for(d, "R8")
        self.assertEqual([f for f in finds if f.rule == "R8"], [])

    def test_r8_comment_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+# eval is dangerous - do not use it
"""
        finds = findings_for(d, "R8")
        self.assertEqual([f for f in finds if f.rule == "R8"], [])

    def test_r7_js_try_catch_resets_scope(self):
        # regression (reviewer): after '} catch (e) {' the try scope must
        # close for JS too - a post-catch conversion is unguarded again
        d = """diff --git a/x.js b/x.js
--- a/x.js
+++ b/x.js
@@ -1 +1,7 @@
 ok
+try {
+  const p = parseInt(req.query.page);
+} catch (e) {
+  console.error(e);
+}
+const n = Number(req.body.count);
"""
        finds = findings_for(d, "R7")
        self.assertTrue(any(f.line == 7 and f.rule == "R7" for f in finds))

    def test_r8_function_definition_not_flagged(self):
        # regression (reviewer): a user function named compile is a
        # definition, not a call - MEDIUM false positive on clean code
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+def compile(src):
+    return src
"""
        finds = findings_for(d, "R8")
        self.assertEqual([f for f in finds if f.rule == "R8"], [])

    def test_r8_shell_true_multiline(self):
        # regression (reviewer): shell=True on a later line of an open
        # subprocess call must fire, reported on the call line
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,6 @@
 ok
+subprocess.run(
+    cmd,
+    shell=True,
+)
"""
        finds = findings_for(d, "R8")
        self.assertTrue(any(f.line == 2 and "shell=True" in f.message for f in finds))

    # --- R9 missing path validation -------------------------------------
    def test_r9_path_from_input(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+p = Path(input("file: "))
"""
        finds = findings_for(d, "R9")
        self.assertTrue(any(f.rule == "R9" and f.severity == "MEDIUM" for f in finds))

    def test_r9_path_from_request(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+data = open(req.files["upload"])
"""
        finds = findings_for(d, "R9")
        self.assertTrue(any("path-traversal" in f.message for f in finds))

    def test_r9_user_input_variable(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+out = Path(user_input)
"""
        finds = findings_for(d, "R9")
        self.assertTrue(any(f.rule == "R9" for f in finds))

    def test_r9_fixed_paths_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+cfg = Path(CONFIG_DIR) / "app.json"
+with open(LOG_FILE) as fh:
+    raw = fh.read()
"""
        finds = findings_for(d, "R9")
        self.assertEqual([f for f in finds if f.rule == "R9"], [])

    def test_r9_non_python_skipped(self):
        d = """diff --git a/x.js b/x.js
--- a/x.js
+++ b/x.js
@@ -1 +1,2 @@
 ok
+const p = Path(input("file"));
"""
        finds = findings_for(d, "R9")
        self.assertEqual([f for f in finds if f.rule == "R9"], [])

    def test_r9_docstring_prose_skipped(self):
        # docstring prose mentioning the patterns is not code (mirror of
        # the R3/R7 docstring refinement)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,7 @@
 ok
+def load_path():
+    """Builds Path(input("file")) and open(sys.argv[0]) paths.
+    Sanitized before use.
+    """
+    pass
+p = Path(input("file: "))
'''
        finds = findings_for(d, "R9")
        # docstring lines (3-5) stay silent...
        self.assertEqual([f for f in finds if f.line in (3, 4, 5)], [])
        # ...the real path-from-input after the docstring is still flagged
        self.assertTrue(any(f.line == 7 for f in finds))

    def test_r9_one_line_docstring_skipped(self):
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+    """Builds Path(input("f")) for the user."""
'''
        finds = findings_for(d, "R9")
        self.assertEqual([f for f in finds if f.rule == "R9"], [])

    def test_r9_trailing_comment_skipped(self):
        # a trailing comment mentioning the pattern is not code: the '#'
        # strip must remove it before matching (regression: raw-line scan
        # fired on the comment text)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+x = 1  # Path(input("f")) is sanitized upstream
+p = Path(input("file: "))
'''
        finds = findings_for(d, "R9")
        self.assertEqual([f for f in finds if f.line == 2], [])
        self.assertTrue(any(f.line == 3 for f in finds))

    def test_r9_docstring_opener_in_context_silenced(self):
        # the docstring opener is an unchanged context line: added prose
        # rows inside it are not code (mirror of R3's context fix)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 """
+R9 reads Path(input("port")) from the user.
+R9 opens sys.argv[1] without checks.
+R9 maps request.files paths directly.
 """
'''
        finds = findings_for(d, "R9")
        self.assertEqual([f for f in finds if f.rule == "R9"], [])

    # --- R10 broad exception handlers ------------------------------------
    def test_r10_broad_except_with_body(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,5 @@
 ok
+try:
+    risky()
+except Exception as e:
+    logger.error(e)
"""
        finds = findings_for(d, "R10")
        self.assertTrue(any(f.rule == "R10" and f.severity == "MEDIUM" for f in finds))

    def test_r10_swallow_shape_left_to_r2(self):
        # R2 owns the swallow-shapes - R10 must not double-fire on them
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,5 @@
 ok
+try:
+    risky()
+except Exception:
+    pass
"""
        finds = findings_for(d, "R10")
        self.assertEqual([f for f in finds if f.rule == "R10"], [])

    def test_r10_specific_exception_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,5 @@
 ok
+try:
+    risky()
+except ValueError:
+    handle()
"""
        finds = findings_for(d, "R10")
        self.assertEqual([f for f in finds if f.rule == "R10"], [])

    def test_r10_docstring_prose_skipped(self):
        # docstring prose mentioning the patterns is not code (mirror of
        # the R3/R7/R9 docstring refinement)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,8 @@
 ok
+try:
+    risky()
+except Exception as e:
+    logger.error(e)
+def handle():
+    """except Exception is discouraged; catch BaseException carefully.
+    """
'''
        finds = findings_for(d, "R10")
        # docstring lines (7-8) stay silent...
        self.assertEqual([f for f in finds if f.line in (7, 8)], [])
        # ...the real broad handler with a body is still flagged
        self.assertTrue(any(f.line == 4 for f in finds))

    def test_r10_one_line_docstring_skipped(self):
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+    """except Exception is discouraged here."""
'''
        finds = findings_for(d, "R10")
        self.assertEqual([f for f in finds if f.rule == "R10"], [])

    def test_r10_trailing_comment_skipped(self):
        # a trailing comment mentioning the pattern is not code: the '#'
        # strip must remove it before matching
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,6 @@
 ok
+x = 1  # except Exception handled upstream in handlers.py
+try:
+    risky()
+except Exception as e:
+    logger.error(e)
'''
        finds = findings_for(d, "R10")
        # comment line (2) stays silent...
        self.assertEqual([f for f in finds if f.line == 2], [])
        # ...the real broad handler is still flagged
        self.assertTrue(any(f.line == 5 for f in finds))

    def test_r10_docstring_opener_in_context_silenced(self):
        # the docstring opener is an unchanged context line: added prose
        # rows inside it are not code (mirror of R3's context fix)
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 """
+R10 mentions except Exception in prose.
+R10 catches BaseException in prose too.
+R10 documents the policy.
 """
'''
        finds = findings_for(d, "R10")
        self.assertEqual([f for f in finds if f.rule == "R10"], [])

    # --- R11 TODO/FIXME markers ------------------------------------------
    def test_r11_todo_marker(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+# TODO: refactor this
+data = process(x)
"""
        finds = findings_for(d, "R11")
        self.assertTrue(any(f.rule == "R11" and f.severity == "LOW" for f in finds))

    def test_r11_no_marker_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+result = process(data)
"""
        finds = findings_for(d, "R11")
        self.assertEqual([f for f in finds if f.rule == "R11"], [])

    def test_r11_lowercase_identifiers_ok(self):
        # regression (reviewer): lowercase todo/hack are identifiers, not markers
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+todo = process(x)
+hack = parse(x)
+xxx = 1
"""
        finds = findings_for(d, "R11")
        self.assertEqual([f for f in finds if f.rule == "R11"], [])

    def test_r11_prose_mention_in_docstring_ok(self):
        # dogfood class: prose that merely names the markers (rule docstrings,
        # README rows, RULE_INFO) must not fire - only the annotation shape counts
        d = '''diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+    """R11: TODO/FIXME/XXX/HACK markers left in added lines.
+    Unfinished work should be tracked, not committed silently.
+    """
'''
        finds = findings_for(d, "R11")
        self.assertEqual([f for f in finds if f.rule == "R11"], [])

    def test_r11_prose_mention_in_trailing_comment_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+x = 1  # the TODO list lives in issues.md
"""
        finds = findings_for(d, "R11")
        self.assertEqual([f for f in finds if f.rule == "R11"], [])

    def test_r11_bare_marker_without_colon_ok(self):
        # documented tradeoff: colon-less '# TODO handle' is not flagged -
        # the : / ( shapes cover the dominant convention without prose noise
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+# TODO handle this without a colon
"""
        finds = findings_for(d, "R11")
        self.assertEqual([f for f in finds if f.rule == "R11"], [])

    def test_r11_owner_tag_and_all_variants_fire(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,6 @@
 ok
+# TODO(jsmith): fix the retry loop
+# FIXME: returns None on empty
+# XXX: leaks the connection
+# HACK: sleeps to dodge the race
"""
        finds = findings_for(d, "R11")
        fired = [f for f in finds if f.rule == "R11"]
        self.assertEqual(len(fired), 4)

    def test_r11_backtick_quoted_mention_ok(self):
        # reviewer: docs write rule names backtick-wrapped - "`TODO:`" is a
        # mention, not an annotation (the lookbehind guard)
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+use the `TODO:` annotation shape in comments
"""
        finds = findings_for(d, "R11")
        self.assertEqual([f for f in finds if f.rule == "R11"], [])

    def test_r11_bare_marker_at_eol_fires(self):
        # the \s*$ branch: a bare marker at end-of-line is still an annotation
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+# TODO
"""
        finds = findings_for(d, "R11")
        self.assertTrue(any(f.rule == "R11" for f in finds))

    def test_r10_inline_swallow_left_to_r2(self):
        # regression (reviewer): one-line 'except Exception: pass' is R2's
        # terrain - R10 must not double-fire on it
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+try:
+    risky()
+except Exception: pass
"""
        finds = findings_for(d, "R10")
        self.assertEqual([f for f in finds if f.rule == "R10"], [])

    def test_r9_config_user_home_ok(self):
        # regression (reviewer): user_home / user_profile are server-side
        # config paths, not user-controlled input
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+home = Path(user_home)
+prof = Path(user_profile) / "settings.json"
"""
        finds = findings_for(d, "R9")
        self.assertEqual([f for f in finds if f.rule == "R9"], [])

    # --- R12 hardcoded config credentials ------------------------------
    def test_r12_connection_string(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+db = "postgres://admin:hunter2@prod-db:5432/app"
"""
        finds = findings_for(d, "R12")
        self.assertTrue(any(f.rule == "R12" and f.severity == "HIGH" for f in finds))

    def test_r12_jwt_token(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
"""
        finds = findings_for(d, "R12")
        self.assertTrue(any("JWT" in f.message for f in finds))

    def test_r12_env_and_sqlite_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+cfg = os.environ["DATABASE_URL"]
+local = "sqlite:///app.db"
"""
        finds = findings_for(d, "R12")
        self.assertEqual([f for f in finds if f.rule == "R12"], [])

    # --- R13 unsafe deserialization ------------------------------------
    def test_r13_pickle(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+data = pickle.loads(raw)
"""
        finds = findings_for(d, "R13")
        self.assertTrue(any(f.rule == "R13" and f.severity == "HIGH" for f in finds))

    def test_r13_yaml_load(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+cfg = yaml.load(stream)
"""
        finds = findings_for(d, "R13")
        self.assertTrue(any("yaml" in f.message for f in finds))

    def test_r13_xml_xxe(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+tree = xml.etree.ElementTree.parse(fh)
"""
        finds = findings_for(d, "R13")
        self.assertTrue(any(f.rule == "R13" and f.severity == "MEDIUM" for f in finds))

    def test_r13_safe_alternatives_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,4 @@
 ok
+cfg = yaml.safe_load(stream)
+data = json.loads(raw)
+enc = pickle.dumps(obj)
"""
        finds = findings_for(d, "R13")
        self.assertEqual([f for f in finds if f.rule == "R13"], [])

    # --- R14 SQL injection ---------------------------------------------
    def test_r14_fstring_execute(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+cur.execute(f"SELECT * FROM users WHERE id={uid}")
"""
        finds = findings_for(d, "R14")
        self.assertTrue(any(f.rule == "R14" and f.severity == "HIGH" for f in finds))

    def test_r14_js_template_query(self):
        d = """diff --git a/x.js b/x.js
--- a/x.js
+++ b/x.js
@@ -1 +1,2 @@
 ok
+conn.query(`SELECT * FROM t WHERE name = '${name}'`)
"""
        finds = findings_for(d, "R14")
        self.assertTrue(any("template literal" in f.message for f in finds))

    def test_r14_concat_and_format(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+cur.execute("SELECT * FROM t WHERE x=" + val)
+cur.execute("SELECT {} FROM t".format(col))
"""
        finds = findings_for(d, "R14")
        self.assertEqual(len([f for f in finds if f.rule == "R14"]), 2)

    def test_r14_parameterized_ok(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
+cur.execute("SELECT 1")
"""
        finds = findings_for(d, "R14")
        self.assertEqual([f for f in finds if f.rule == "R14"], [])

    def test_r14_parameterized_with_computed_arg_ok(self):
        # regression (reviewer): a computed PARAMETER is not SQL string-building
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+cur.execute("SELECT * FROM t", (a + b,))
"""
        finds = findings_for(d, "R14")
        self.assertEqual([f for f in finds if f.rule == "R14"], [])

    def test_r14_non_sql_text_ok(self):
        # regression (reviewer): text() is a common non-SQL function name
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+label = text(f"hello {name}")
"""
        finds = findings_for(d, "R14")
        self.assertEqual([f for f in finds if f.rule == "R14"], [])

    def test_r13_yaml_load_all(self):
        # regression (reviewer): load_all is unsafe too (FullLoader default)
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+docs = yaml.load_all(stream)
"""
        finds = findings_for(d, "R13")
        self.assertTrue(any(f.rule == "R13" and f.severity == "HIGH" for f in finds))

    def test_r13_pickle_unpickler(self):
        # regression (reviewer): Unpickler also loads pickles
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
 ok
+up = pickle.Unpickler(fh)
"""
        finds = findings_for(d, "R13")
        self.assertTrue(any(f.rule == "R13" and f.severity == "HIGH" for f in finds))

# ===========================================================================
# gate / severity model
# ===========================================================================
class TestGate(unittest.TestCase):
    def _mk(self, sev):
        return cd.Finding(sev, "R1", "f.py", 1, "m", "s")

    def test_fail_on_high(self):
        self.assertFalse(cd.gate_verdict([self._mk("HIGH")], "high")[0])
        self.assertTrue(cd.gate_verdict([self._mk("MEDIUM")], "high")[0])
        self.assertTrue(cd.gate_verdict([], "high")[0])

    def test_fail_on_medium(self):
        self.assertFalse(cd.gate_verdict([self._mk("MEDIUM")], "medium")[0])
        self.assertFalse(cd.gate_verdict([self._mk("HIGH")], "medium")[0])
        self.assertTrue(cd.gate_verdict([self._mk("LOW")], "medium")[0])

    def test_fail_on_none_never_fails(self):
        self.assertTrue(cd.gate_verdict([self._mk("HIGH")], "none")[0])

    def test_exit_codes(self):
        rc, out = run_tool("--file", str(HERE / "_test_diff.py"))
        # no secrets in this file -> gate passes
        self.assertEqual(rc, 0)
        self.assertIn("GATE: PASS", out)


# ===========================================================================
# error-log tooling
# ===========================================================================
LOG_SAMPLE = """[2026-08-11] AREA: first bug
  ERROR: something broke
  CAUSE: a root cause
  FIX: the fix
  STATUS: FIXED.

[2026-08-11] AREA: still open
  ERROR: still broken
  CAUSE: unknown
  FIX:
  STATUS: OPEN.
"""

LOG_BAD = """[2026-08-11] AREA: missing fields
  ERROR: only an error
  STATUS: FIXED.
"""


class TestLogTooling(unittest.TestCase):
    def test_parse_entries(self):
        entries = cd.parse_entries(LOG_SAMPLE)
        self.assertEqual([e["area"] for e in entries], ["first bug", "still open"])

    def test_validate_good(self):
        rc, problems = cd.validate_log(LOG_SAMPLE)
        self.assertEqual(rc, 0)

    def test_validate_bad_missing_fields(self):
        rc, problems = cd.validate_log(LOG_BAD)
        self.assertEqual(rc, 1)
        self.assertTrue(any("missing CAUSE" in p for p in problems))
        self.assertTrue(any("missing FIX" in p for p in problems))

    def test_validate_bad_status(self):
        text = LOG_SAMPLE.replace("STATUS: OPEN.", "STATUS: SOMEDAY.")
        rc, problems = cd.validate_log(text)
        self.assertEqual(rc, 1)
        self.assertTrue(any("unknown STATUS" in p for p in problems))

    def test_extract_area(self):
        self.assertEqual(cd.extract_area("fix thing (AREA: the bug)"), "the bug")
        self.assertEqual(cd.extract_area("fix thing (AREA: the bug) (#31)"), "the bug")
        self.assertEqual(cd.extract_area("no marker here"), "")
        self.assertEqual(cd.extract_area("docs only"), "")

    def test_extract_area_family_contract(self):
        # first marker-bearing line wins; on that line the LAST marker wins
        # (greedy-sed semantics shared with the shell hooks and siblings)
        self.assertEqual(
            cd.extract_area("fix: x (AREA: first) then (AREA: second)"), "second"
        )
        self.assertEqual(
            cd.extract_area("feat: y\n\nbody (AREA: real area) (LOG: other)"), "other"
        )
        # first LINE wins even if a later line also carries a marker
        self.assertEqual(
            cd.extract_area("fix: a (AREA: subject)\n(AREA: body marker)"), "subject"
        )
        # LOG: works and squash-merge suffix is stripped
        self.assertEqual(
            cd.extract_area("fix: docs (LOG: doc fix) (#44)"), "doc fix"
        )

    def test_has_entry(self):
        self.assertEqual(cd.cmd_has_entry(LOG_SAMPLE, "first bug"), 0)
        self.assertEqual(cd.cmd_has_entry(LOG_SAMPLE, "first"), 0)  # substring
        self.assertEqual(cd.cmd_has_entry(LOG_SAMPLE, "nope"), 1)

    def test_insert_entry_places_before_template(self):
        text = "header\n\n[2026-08-11] AREA: x\n  ERROR: e\n  CAUSE: c\n  FIX: f\n  STATUS: FIXED.\n\n5) TO ADD A NEW ENTRY\n"
        out = cd._insert_entry(text, "[2026-08-11] AREA: y\n  ERROR: e\n  CAUSE: c\n  FIX:\n  STATUS: OPEN.\n")
        # y is appended after x but BEFORE the template section
        self.assertLess(out.find("AREA: x"), out.find("AREA: y"))
        self.assertLess(out.find("AREA: y"), out.find("5) TO ADD A NEW ENTRY"))
        self.assertEqual([e["area"] for e in cd.parse_entries(out)], ["x", "y"])

    def test_insert_entry_goes_before_example_section(self):
        # regression: entries must land in the ACTIVE section, before the
        # EXAMPLE header, so parse_entries can see them
        text = ("header\n\n"
                "[2026-08-11] AREA: real\n  ERROR: e\n  CAUSE: c\n  FIX: f\n  STATUS: FIXED.\n\n"
                "EXAMPLE ENTRIES (replace with your own)\n\n"
                "[2026-08-05] AREA: example\n  ERROR: e\n  CAUSE: c\n  FIX: f\n  STATUS: FIXED.\n\n"
                "5) TO ADD A NEW ENTRY\n")
        out = cd._insert_entry(text, "[2026-08-11] AREA: fresh\n  ERROR: e\n  CAUSE: c\n  FIX:\n  STATUS: OPEN.\n")
        self.assertLess(out.find("AREA: fresh"), out.find("EXAMPLE ENTRIES"))
        entries = [e["area"] for e in cd.parse_entries(out)]
        self.assertEqual(entries, ["real", "fresh"])  # example excluded, fresh visible

    def test_parse_entries_marker_in_body_does_not_truncate(self):
        # regression: an entry whose CAUSE mentions 'EXAMPLE ENTRIES' must
        # not cut the parse region (anchored markers)
        text = ("header\n\n"
                "[2026-08-11] AREA: talks about sections\n  ERROR: e\n"
                "  CAUSE: mentions EXAMPLE ENTRIES in the body\n  FIX: f\n  STATUS: FIXED.\n\n"
                "[2026-08-11] AREA: after it\n  ERROR: e\n  CAUSE: c\n  FIX: f\n  STATUS: FIXED.\n\n"
                "EXAMPLE ENTRIES (replace with your own)\n\n"
                "5) TO ADD A NEW ENTRY\n")
        entries = cd.parse_entries(text)
        self.assertEqual([e["area"] for e in entries],
                         ["talks about sections", "after it"])
        self.assertIn("EXAMPLE ENTRIES",
                      entries[0]["fields"]["CAUSE"])  # body survived intact

    def test_archive_moves_not_duplicates(self):
        # regression: an archived entry must disappear from the ACTIVE
        # section and appear exactly once, in the ARCHIVED block
        text = ("HEADER\n\n"
                "[2020-01-01] AREA: old bug\n  ERROR: e\n  CAUSE: c\n  FIX: f\n  STATUS: FIXED.\n\n"
                "[2026-08-11] AREA: new bug\n  ERROR: e\n  CAUSE: c\n  FIX: f\n  STATUS: OPEN.\n\n"
                "5) TO ADD A NEW ENTRY\n")
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "errors.txt"
            log.write_text(text, encoding="utf-8")
            self.assertEqual(cd.cmd_archive(log, 30, apply=True), 0)
            out = log.read_text(encoding="utf-8")
            self.assertEqual(out.count("AREA: old bug"), 1)  # moved, not duplicated
            self.assertEqual(out.count("AREA: new bug"), 1)
            self.assertIn("ARCHIVED ENTRIES", out)
            self.assertIn("HEADER", out)  # reviewer: header must survive
            active = [e["area"] for e in cd.parse_entries(out)]
            self.assertEqual(active, ["new bug"])  # old bug no longer active


# ===========================================================================
# process-style output-value integration tests (the family standard)
# ===========================================================================
SECRET_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,5 +1,8 @@
 def main():
     cfg = load()
+    api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
+    try:
+        save(cfg)
+    except:
+        pass
     return cfg
"""

CLEAN_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,5 +1,7 @@
 def main():
     cfg = load()
+    with open("cache.json") as fh:
+        data = fh.read()
     return cfg
"""


class TestIntegration(unittest.TestCase):
    def test_secret_diff_gate_fails_with_output_values(self):
        rc, out = run_tool("--stdin", "--rule", "R1,R2", stdin=SECRET_DIFF)
        self.assertEqual(rc, 1)
        self.assertIn("[HIGH] R1 hardcoded-secrets", out)
        self.assertIn("app.py:7", out)
        self.assertIn("GATE: FAIL", out)

    def test_clean_diff_gate_passes(self):
        rc, out = run_tool("--stdin", stdin=CLEAN_DIFF)
        self.assertEqual(rc, 0)
        self.assertIn("GATE: PASS", out)

    def test_json_output_shape(self):
        rc, out = run_tool("--stdin", "--json", stdin=SECRET_DIFF)
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["gate"], "FAIL")
        self.assertTrue(any(f["rule"] == "R1" and f["severity"] == "HIGH"
                            for f in payload["findings"]))
        for f in payload["findings"]:
            for key in ("rule", "name", "severity", "file", "line",
                        "message", "suggestion"):
                self.assertIn(key, f)

    def test_warn_only_exits_zero(self):
        rc, out = run_tool("--stdin", "--warn-only", stdin=SECRET_DIFF)
        self.assertEqual(rc, 0)
        self.assertIn("GATE: PASS", out)
        self.assertIn("sk-", out)  # findings still reported

    def test_fail_on_medium_flips_gate(self):
        rc_high, _ = run_tool("--stdin", stdin=SECRET_DIFF)
        rc_med, out = run_tool("--stdin", "--fail-on", "medium", stdin=SECRET_DIFF)
        self.assertEqual(rc_high, 1)
        self.assertEqual(rc_med, 1)  # still fails: it has HIGH + MEDIUM

    def test_rule_filter_limits_findings(self):
        rc, out = run_tool("--stdin", "--rule", "R1", stdin=SECRET_DIFF)
        self.assertIn("[HIGH] R1", out)
        self.assertNotIn("R2", out.split("\n")[4] if len(out.split("\n")) > 4 else "")

    def test_missing_file_clean_error(self):
        rc, out = run_tool("--file", "definitely-not-here.diff")
        self.assertEqual(rc, 2)
        self.assertNotIn("Traceback", out)
        self.assertIn("cannot read", out)

    def test_unknown_rule_usage_error(self):
        rc, out = run_tool("--stdin", "--rule", "R99", stdin=CLEAN_DIFF)
        self.assertEqual(rc, 2)
        self.assertIn("unknown rule", out)

    def test_empty_stdin_passes(self):
        rc, out = run_tool("--stdin", stdin="")
        self.assertEqual(rc, 0)
        self.assertIn("GATE: PASS", out)

    def test_max_findings_caps(self):
        rc, out = run_tool("--stdin", "--max-findings", "1", "--json", stdin=SECRET_DIFF)
        payload = json.loads(out)
        self.assertLessEqual(len(payload["findings"]), 1)

    def test_exclude_skips_file(self):
        rc, out = run_tool("--stdin", "--exclude", "app.py", stdin=SECRET_DIFF)
        self.assertEqual(rc, 0)
        self.assertIn("GATE: PASS", out)

    def test_new_rules_r6_r7_r8_process(self):
        # every rule must be reachable through the real CLI (process-style)
        d = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,5 +1,8 @@
 def main():
     cfg = load()
+    url = "https://api.stripe.com/v1"
+    port = int(input("port: "))
+    result = eval(user_code)
     return cfg
"""
        rc, out = run_tool("--stdin", "--rule", "R6,R7,R8", "--fail-on", "medium", "--json", stdin=d)
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["gate"], "FAIL")
        self.assertEqual({f["rule"] for f in payload["findings"]}, {"R6", "R7", "R8"})

    def test_new_rules_r9_r10_r11_process(self):
        # every rule must be reachable through the real CLI (process-style)
        d = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,5 +1,9 @@
 def main():
     cfg = load()
+    path = Path(input("file: "))
+    try:
+        risky()
+    except Exception as e:
+        log(e)
+    # TODO: wire up retries
     return cfg
"""
        rc, out = run_tool("--stdin", "--rule", "R9,R10,R11", "--fail-on", "medium",
                           "--json", stdin=d)
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["gate"], "FAIL")
        self.assertEqual({f["rule"] for f in payload["findings"]}, {"R9", "R10", "R11"})

    def test_new_rules_r12_r13_r14_process(self):
        # R12-R14 are HIGH (and R13 XML is MEDIUM) - the default gate must FAIL
        d = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,5 +1,8 @@
 def main():
     cfg = load()
+    db = "postgres://admin:hunter2@prod-db/app"
+    data = pickle.loads(raw)
+    cur.execute(f"SELECT * FROM users WHERE id={uid}")
     return cfg
"""
        rc, out = run_tool("--stdin", "--rule", "R12,R13,R14", "--json", stdin=d)
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["gate"], "FAIL")
        self.assertEqual({f["rule"] for f in payload["findings"]}, {"R12", "R13", "R14"})

    def test_version(self):
        rc, out = run_tool("--version")
        self.assertEqual(rc, 0)
        self.assertIn(cd.VERSION, out)
        # the release contract: CHANGELOG's first versioned header is the
        # single source of truth (release.yml tags from it) and must match
        # the code's VERSION constant - drift here means a mislabeled bump
        changelog = (HERE / "CHANGELOG.md").read_text(encoding="utf-8")
        versioned = next((ln for ln in changelog.splitlines()
                          if ln.startswith("## [") and "Unreleased" not in ln),
                         None)
        self.assertIsNotNone(versioned, "no versioned CHANGELOG header found")
        self.assertEqual(versioned[4:].split("]", 1)[0], cd.VERSION)

    def test_add_has_entry_check_commit_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "errors.txt"
            log.write_text("header\n\n", encoding="utf-8")
            # --logfile keeps the repo's own errors.txt untouched
            rc, _ = run_tool("--logfile", str(log), "--add", "--area", "probe area",
                             "--error", "probe error", "--cause", "probe cause",
                             "--status", "OPEN")
            self.assertEqual(rc, 0)
            self.assertEqual(cd.parse_entries(log.read_text(encoding="utf-8"))[0]["area"],
                             "probe area")
            rc0, out0 = run_tool("--logfile", str(log), "--has-entry", "probe area")
            self.assertEqual(rc0, 0)
            self.assertIn("is logged", out0)
            rc1, out1 = run_tool("--logfile", str(log), "--has-entry", "not logged area")
            self.assertEqual(rc1, 1)
            self.assertIn("BLOCKED", out1)
            # commit-message gate
            msg = Path(tmp) / "msg.txt"
            msg.write_text("fix probe (AREA: probe area)", encoding="utf-8")
            rc2, out2 = run_tool("--logfile", str(log), "--check-commit", str(msg))
            self.assertEqual(rc2, 0)
            self.assertIn("OK", out2)
            msg.write_text("fix without marker", encoding="utf-8")
            rc3, out3 = run_tool("--logfile", str(log), "--check-commit", str(msg))
            self.assertEqual(rc3, 1)
            self.assertIn("BLOCKED", out3)

    def test_git_modes_real_repo(self):
        """--range and --staged must work in a real git repo (regression:
        the source label was mistaken for an error and both modes always
        exited 2; the suite only ever tested --stdin/--file)."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def g(*args):
                return subprocess.run(["git", *args], cwd=repo,
                                      capture_output=True, text=True,
                                      encoding="utf-8", errors="replace")

            g("init", "-q")
            g("config", "user.email", "t@t")
            g("config", "user.name", "t")
            (repo / "f.py").write_text("x = 1\n", encoding="utf-8")
            g("add", "f.py")
            g("commit", "-q", "-m", "base")
            (repo / "f.py").write_text(
                "x = 1\napi_key = 'sk-abcdefghijklmnopqrstuvwxyz1234567890'\n",
                encoding="utf-8")
            g("add", "f.py")
            g("commit", "-q", "-m", "change")

            # --range across the two commits
            rc, out = run_tool_in(repo, "--range", "HEAD~1", "HEAD", "--json")
            self.assertEqual(rc, 1, f"--range should FAIL the gate: {out[:200]}")
            payload = json.loads(out)
            self.assertEqual(payload["gate"], "FAIL")
            self.assertEqual(payload["changed"], 1)
            self.assertTrue(any(f["rule"] == "R1" for f in payload["findings"]))

            # --staged: stage a real finding so the gate must FAIL
            (repo / "f.py").write_text(
                (repo / "f.py").read_text(encoding="utf-8")
                + "password = 'hunter2'\n",
                encoding="utf-8")
            g("add", "f.py")
            rc2, out2 = run_tool_in(repo, "--staged", "--json")
            payload2 = json.loads(out2)
            self.assertEqual(payload2["gate"], "FAIL")
            self.assertEqual(payload2["source"], "git diff --cached")
            self.assertTrue(any(
                "hunter2" in f["message"] or "hunter2" in f["suggestion"]
                for f in payload2["findings"]))

    def test_git_modes_outside_repo_clean_error(self):
        """--staged outside a git repo must give a clean one-line error, not
        git's raw usage dump (regression: finding #3 from the 500-test run -
        git diff fell back to --no-index mode and leaked its whole usage
        screen; the gate now probes `git rev-parse --is-inside-work-tree`
        first). Exit code stays 2 (environment error)."""
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run_tool_in(tmp, "--staged")
            self.assertEqual(rc, 2)
            self.assertIn("not a git repository", out)
            self.assertNotIn("--pickaxe", out)  # no raw git usage dump
            self.assertNotIn("Traceback", out)

    def test_log_validate_subprocess(self):
        rc, out = run_tool("--log")
        self.assertEqual(rc, 0)
        self.assertIn("log healthy", out)



# ===========================================================================
# plugin interface (rules.d/)
# ===========================================================================
PLUGIN_SRC = '''RULE_ID = "R15"
RULE_NAME = "demo-plugin"
SEVERITY = "MEDIUM"
DESCRIPTION = "flags added lines that call demo()"
SUGGESTION = "remove the demo() call"

def rule_diff(f):
    out = []
    for ln in f.added:
        if "demo()" in ln.text:
            out.append((SEVERITY, RULE_ID, f.path, ln.lineno,
                        "demo() called in an added line", SUGGESTION))
    return out
'''

PLUGIN_DIFF = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+demo()
+x = 1
"""


_PLUGIN_TMP_DIRS: set = set()


def _write_plugin_dir(files):
    """Write {name: content} into a fresh temp dir; return its path.
    Dirs are tracked so the TestPlugins tearDowns can remove them
    (reviewer: mkdtemp leaked a directory per test)."""
    tmp = tempfile.mkdtemp()
    _PLUGIN_TMP_DIRS.add(tmp)
    for name, content in files.items():
        Path(tmp, name).write_text(content, encoding="utf-8")
    return tmp


class TestPlugins(unittest.TestCase):
    def tearDown(self):
        while _PLUGIN_TMP_DIRS:
            shutil.rmtree(_PLUGIN_TMP_DIRS.pop(), ignore_errors=True)

    # --- load + fire through analyze() --------------------------------
    def test_plugin_load_and_fire(self):
        tmp = _write_plugin_dir({"demo_rule.py": PLUGIN_SRC})
        plugins, warnings = cd.load_plugins(Path(tmp))
        self.assertEqual(warnings, [])
        self.assertEqual(set(plugins), {"R15"})
        self.assertEqual(plugins["R15"]["name"], "demo-plugin")
        self.assertEqual(cd.RULE_INFO["R15"]["name"], "demo-plugin")
        finds = cd.analyze(PLUGIN_DIFF, root=HERE, plugins=plugins, max_findings=0)
        hits = [f for f in finds if f.rule == "R15"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "MEDIUM")
        self.assertEqual(hits[0].line, 2)
        self.assertIn("demo()", hits[0].message)
        # without plugins the same diff is clean
        bare = cd.analyze(PLUGIN_DIFF, root=HERE, max_findings=0)
        self.assertEqual([f for f in bare if f.rule == "R15"], [])

    # --- underscore files are templates, never rules -------------------
    def test_plugin_skips_underscore_files(self):
        tmp = _write_plugin_dir({
            "_template.py": PLUGIN_SRC.replace("R15", "R99"),
            "real_rule.py": PLUGIN_SRC.replace("R15", "R16"),
        })
        plugins, warnings = cd.load_plugins(Path(tmp))
        self.assertEqual(warnings, [])
        self.assertEqual(set(plugins), {"R16"})

    # --- broken plugins warn and are skipped, never crash --------------
    def test_plugin_missing_metadata_warns(self):
        tmp = _write_plugin_dir({"broken_rule.py": "SEVERITY = 'LOW'\n"})
        plugins, warnings = cd.load_plugins(Path(tmp))
        self.assertEqual(plugins, {})
        self.assertEqual(len(warnings), 1)
        self.assertIn("missing RULE_ID", warnings[0])
        # an import-time crash is also a warning, not a crash
        tmp2 = _write_plugin_dir({"boom_rule.py": "raise RuntimeError('boom')\n"})
        plugins2, warnings2 = cd.load_plugins(Path(tmp2))
        self.assertEqual(plugins2, {})
        self.assertIn("import failed", warnings2[0])

    # --- bad SEVERITY metadata is rejected -----------------------------
    def test_plugin_bad_severity_warns(self):
        tmp = _write_plugin_dir({"sev_rule.py": PLUGIN_SRC.replace("MEDIUM", "URGENT")})
        plugins, warnings = cd.load_plugins(Path(tmp))
        self.assertEqual(plugins, {})
        self.assertEqual(len(warnings), 1)
        self.assertIn("bad SEVERITY", warnings[0])

    # --- bad finding tuples fall back, never crash ---------------------
    def test_plugin_bad_finding_tuple_falls_back(self):
        src = (PLUGIN_SRC
               .replace("R15", "R17")
               .replace("(SEVERITY, RULE_ID, f.path", '("URGENT", RULE_ID, f.path')
               .replace('"demo() called in an added line", SUGGESTION))',
                        '"demo() called in an added line", ""))'))
        tmp = _write_plugin_dir({"demo_rule.py": src})
        plugins, warnings = cd.load_plugins(Path(tmp))
        self.assertEqual(warnings, [])
        finds = cd.analyze(PLUGIN_DIFF, root=HERE, plugins=plugins, max_findings=0)
        hits = [f for f in finds if f.rule == "R17"]
        self.assertEqual(len(hits), 1)
        # severity 'URGENT' is not valid -> falls back to the module default
        self.assertEqual(hits[0].severity, "MEDIUM")
        # empty suggestion -> falls back to the module SUGGESTION
        self.assertEqual(hits[0].suggestion, "remove the demo() call")

    # --- the real CLI: --list-rules and --rules-dir --------------------
    def test_plugin_list_rules_cli(self):
        tmp = _write_plugin_dir({
            "cli_rule.py": (PLUGIN_SRC
                            .replace("R15", "R18")
                            .replace("demo-plugin", "cli-plugin")),
            "_hidden.py": PLUGIN_SRC.replace("R15", "R99"),
        })
        rc, out = run_tool("--list-rules", "--rules-dir", tmp)
        self.assertEqual(rc, 0)
        self.assertIn("R14", out)          # built-ins listed
        self.assertIn("R18", out)          # plugin listed
        self.assertIn("cli-plugin", out)
        self.assertIn("built-in", out)
        self.assertNotIn("R99", out)       # underscore files skipped
        # the plugin fires through the real CLI and respects --rule/--fail-on
        rc2, out2 = run_tool("--stdin", "--rules-dir", tmp, "--rule", "R18",
                             "--fail-on", "medium", "--json", stdin=PLUGIN_DIFF)
        self.assertEqual(rc2, 1)
        payload = json.loads(out2)
        self.assertEqual(payload["gate"], "FAIL")
        self.assertEqual({f["rule"] for f in payload["findings"]}, {"R18"})
        self.assertEqual(payload["plugins"], ["R18"])
        self.assertEqual(payload["findings"][0]["name"], "cli-plugin")


# ===========================================================================
# plugin interface - reviewer round (malformed returns, scan errors, ghosts)
# ===========================================================================
class TestPluginsReview(unittest.TestCase):
    def tearDown(self):
        while _PLUGIN_TMP_DIRS:
            shutil.rmtree(_PLUGIN_TMP_DIRS.pop(), ignore_errors=True)

    def test_plugin_malformed_return_skipped(self):
        # a plugin returning a bare string must not produce a phantom finding
        src = PLUGIN_SRC.replace("R15", "P2").replace(
            '''            out.append((SEVERITY, RULE_ID, f.path, ln.lineno,
                        "demo() called in an added line", SUGGESTION))
    return out''',
            '''            return "hello!"''')
        tmp = _write_plugin_dir({"bad_rule.py": src})
        plugins, warnings = cd.load_plugins(Path(tmp))
        self.assertEqual(warnings, [])
        finds = cd.analyze(PLUGIN_DIFF, root=HERE, plugins=plugins, max_findings=0)
        self.assertEqual([f for f in finds if f.rule == "P2"], [])

    def test_plugin_scan_exception_warns(self):
        # a rule that raises mid-scan is skipped WITH a stderr warning
        src = PLUGIN_SRC.replace("R15", "P3").replace(
            '''        if "demo()" in ln.text:
            out.append((SEVERITY, RULE_ID, f.path, ln.lineno,
                        "demo() called in an added line", SUGGESTION))
    return out''',
            '''        raise RuntimeError("scan boom")''')
        tmp = _write_plugin_dir({"scan_boom.py": src})
        plugins, _ = cd.load_plugins(Path(tmp))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            finds = cd.analyze(PLUGIN_DIFF, root=HERE, plugins=plugins,
                               max_findings=0)
        self.assertEqual([f for f in finds if f.rule == "P3"], [])
        self.assertIn("scan boom", err.getvalue())
        self.assertIn("scan_boom.py", err.getvalue())

    def test_plugin_foreign_rule_id_normalized(self):
        # a finding tuple with a wrong rule id is normalized to the plugin id
        src = PLUGIN_SRC.replace("R15", "P4").replace(
            "(SEVERITY, RULE_ID, f.path", '("HIGH", "R1", f.path')
        tmp = _write_plugin_dir({"typo_rule.py": src})
        plugins, _ = cd.load_plugins(Path(tmp))
        finds = cd.analyze(PLUGIN_DIFF, root=HERE, plugins=plugins, max_findings=0)
        hits = [f for f in finds if f.rule == "P4"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "HIGH")  # valid severity kept
        self.assertEqual(hits[0].as_dict()["name"], "demo-plugin")

    def test_plugin_rule_info_resets_between_loads(self):
        # RULE_INFO must not keep ghost plugin entries across load_plugins
        tmp1 = _write_plugin_dir({"a_rule.py": PLUGIN_SRC.replace("R15", "P5")})
        cd.load_plugins(Path(tmp1))
        self.assertIn("P5", cd.RULE_INFO)
        tmp2 = _write_plugin_dir({"b_rule.py": PLUGIN_SRC.replace("R15", "P6")})
        cd.load_plugins(Path(tmp2))
        self.assertNotIn("P5", cd.RULE_INFO)  # cleared by the second load
        self.assertIn("P6", cd.RULE_INFO)


# ===========================================================================
# dogfood regression: git integration must survive non-ASCII diffs
# ===========================================================================
class TestDogfoodRegression(unittest.TestCase):
    def test_git_range_unicode_diff_no_crash(self):
        # regression (dogfood): --range crashed with UnicodeDecodeError on
        # diffs containing non-ANSI bytes — _run_git decoded git output with
        # the locale codec (cp1252 on Windows, which has undefined bytes like
        # 0x8F). U+204F encodes to E2 81 8F in UTF-8, so the diff must
        # contain the exact byte that used to kill the reader thread.
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def g(*args):
                return subprocess.run(["git", *args], cwd=repo,
                                      capture_output=True, text=True,
                                      encoding="utf-8", errors="replace")

            g("init", "-q")
            g("config", "user.email", "t@t")
            g("config", "user.name", "t")
            (repo / "f.py").write_text("x = 1\n", encoding="utf-8")
            g("add", ".")
            g("commit", "-q", "-m", "base")
            (repo / "f.py").write_text("x = 1\nnote = '\u204f'\n",
                                       encoding="utf-8")
            g("add", ".")
            g("commit", "-q", "-m", "unicode")
            rc, out = run_tool_in(repo, "--range", "HEAD~1", "HEAD", "--json")
            self.assertNotIn("Traceback", out)
            self.assertNotIn("UnicodeDecodeError", out)
            self.assertIn('"source"', out)  # real JSON payload, not a crash
            self.assertEqual(rc, 0)          # clean diff passes the gate

# ===========================================================================
# security hardening: containment, redaction, display sanitize, input caps
# ===========================================================================
class TestSecurityHardening(unittest.TestCase):
    # --- S1: diff-controlled paths must not read outside the repo ----------
    def test_repo_path_containment(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        good = cd._repo_path(root, "sub/file.py")
        self.assertIsNotNone(good)
        self.assertTrue(str(good.resolve()).startswith(str(root.resolve())))
        self.assertIsNone(cd._repo_path(root, "../outside.py"))
        self.assertIsNone(cd._repo_path(root, str(root / ".." / "outside.py")))
        self.assertIsNone(cd._repo_path(root, "sub/x\x00y.py"))
        self.assertIsNone(cd._repo_path(root, ""))
        if os.name == "nt":
            self.assertIsNone(cd._repo_path(root, "C:/Windows/win.ini"))
            self.assertIsNone(cd._repo_path(root, "\\\\server\\share\\f"))

    @unittest.skipUnless(hasattr(os, "symlink") and os.name != "nt",
                         "needs symlinks")
    def test_repo_path_symlink_escape_rejected(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        root = base / "repo"
        root.mkdir()
        secret = base / "secret.txt"
        secret.write_text("x", encoding="utf-8")
        try:
            (root / "link.py").symlink_to(secret)
        except OSError:
            return  # no symlink support: nothing to prove
        self.assertIsNone(cd._repo_path(root, "link.py"))

    def test_r5_does_not_read_outside_repo(self):
        # S1 integration: a diff naming ../secret.py must not let R5 read it.
        # The outside file defines victim() - R5 would fire if it were read.
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        root = base / "repo"
        root.mkdir()
        (base / "secret.py").write_text("def victim():\n    return 1\n",
                                        encoding="utf-8")
        d = """diff --git a/../secret.py b/../secret.py
--- a/../secret.py
+++ b/../secret.py
@@ -1 +1,2 @@
 ok
+def victim():
"""
        finds = findings_for(d, "R5", root=root)
        self.assertEqual([f for f in finds if f.rule == "R5"], [])

    # --- S2: R4 must redact secrets from its snippet ------------------------
    def test_r4_redacts_secret_in_snippet(self):
        d = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,3 @@
 ok
+password = "sk-abcdefghijklmnopqrstuvwxyz123456"
+password = "sk-abcdefghijklmnopqrstuvwxyz123456"
"""
        finds = findings_for(d, "R4")
        r4 = [f for f in finds if f.rule == "R4"]
        self.assertTrue(r4)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", r4[0].message)
        self.assertIn("redacted", r4[0].message)

    # --- S3: terminal/bidi control chars are stripped from report text ------
    def test_display_safe_strips_control(self):
        raw = "\x1b[31mred\x1b[0m\t\u202eEND"
        clean = cd._display_safe(raw)
        self.assertNotIn("\x1b", clean)
        self.assertNotIn("\u202e", clean)
        self.assertNotIn("\t", clean)

    def test_path_control_chars_sanitized_in_report(self):
        d = """diff --git a/x\x1b[31m.py b/x\x1b[31m.py
--- a/x\x1b[31m.py
+++ b/x\x1b[31m.py
@@ -1 +1,2 @@
 ok
+key = "sk-abcdefghijklmnopqrstuvwxyz123456"
"""
        finds = findings_for(d, "R1")
        self.assertTrue(finds)
        for f in finds:
            self.assertNotIn("\x1b", f.file)

    # --- S4: untrusted diff input is size-capped ----------------------------
    def test_file_input_size_cap(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = d / "big.diff"
        p.write_text("diff --git a/x b/x\n" * 500, encoding="utf-8")
        with mock.patch.object(cd, "MAX_DIFF_BYTES", 100):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cd.main(["--file", str(p)])
        self.assertEqual(rc, 2)
        self.assertIn("exceeds", out.getvalue())

    def test_stdin_input_size_cap(self):
        with mock.patch.object(cd, "MAX_DIFF_BYTES", 100), \
                mock.patch("sys.stdin", io.StringIO("x" * 500)):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cd.main(["--stdin"])
        self.assertEqual(rc, 2)
        self.assertIn("exceeds", out.getvalue())

    # --- S5: the product path never leaks a raw traceback -------------------
    def test_plugin_bad_field_types_serialize_cleanly(self):
        # S5 review: a plugin returning non-serializable fields must not
        # crash json.dumps outside the boundary guard - fields are coerced
        class _Obj:
            pass

        def rule_diff(f):
            o = _Obj()
            return [("LOW", "P9", o, o, o, o)]

        plugins = {"P9": {"id": "P9", "severity": "LOW",
                          "suggestion": "fix it", "func": rule_diff,
                          "file": "bad.py"}}
        d = """diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1,2 @@
 ok
+data = 1
"""
        finds = cd.analyze(d, root=Path("."), plugins=plugins, max_findings=0)
        self.assertTrue(any(f.rule == "P9" for f in finds))
        payload = {"findings": [f.as_dict() for f in finds]}
        self.assertIsInstance(json.dumps(payload), str)  # must not raise

    def test_main_internal_error_no_traceback(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = d / "ok.diff"
        p.write_text("diff --git a/x b/x\n--- a/x\n+++ b/x\n"
                     "@@ -1 +1,2 @@\n ok\n+x = 1\n", encoding="utf-8")
        with mock.patch.object(cd, "parse_diff",
                               side_effect=RuntimeError("boom")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cd.main(["--file", str(p)])
        self.assertEqual(rc, 2)
        self.assertIn("internal error", out.getvalue())
        self.assertNotIn("Traceback", out.getvalue())


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    ok = result.wasSuccessful()
    count = result.testsRun
    print(f"\nAll {count} tests passed" if ok else f"\n{count} tests, FAILURES")
    sys.exit(0 if ok else 1)
