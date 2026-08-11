"""Tests for check_diff.py — Agent Diff Gate.

Covers the diff parser, all five rules (happy + negative + edge cases), the
gate exit-code model, the error-log tooling, and process-style output-value
integration tests (rule: verify OUTPUT VALUES, not just exit codes).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
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
        finds = findings_for(d, "R6")
        self.assertEqual([f for f in finds if f.rule == "R6"], [])

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

    # --- R8 dangerous eval/exec -----------------------------------------
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

    # --- R10 broad exception handlers -----------------------------------
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

    # --- R11 TODO/FIXME markers ----------------------------------------
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
        self.assertEqual(cd.extract_area("no marker here"), "")
        self.assertEqual(cd.extract_area("docs only"), "")

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
        self.assertIn("0.1.0", out)

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

    def test_log_validate_subprocess(self):
        rc, out = run_tool("--log")
        self.assertEqual(rc, 0)
        self.assertIn("log healthy", out)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    ok = result.wasSuccessful()
    count = result.testsRun
    print(f"\nAll {count} tests passed" if ok else f"\n{count} tests, FAILURES")
    sys.exit(0 if ok else 1)
