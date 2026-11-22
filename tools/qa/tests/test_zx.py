"""Tests for tools/qa/zx.py, the guarded entry for a session without hooks (WI-2): deny, allow, fail-closed
guards, and output withheld by the scan."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import zx  # noqa: E402


def _script(body):
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    f.write(body)
    f.close()
    return f.name


ALLOW = _script("import sys; sys.stdin.read()\n")
DENY = _script('import sys, json; sys.stdin.read(); print(json.dumps({"hookSpecificOutput": '
               '{"permissionDecision": "deny", "permissionDecisionReason": "no"}}))\n')
CRASH = _script("import sys; sys.stdin.read(); sys.exit(1)\n")
JUNK = _script("import sys; sys.stdin.read(); print('hello')\n")
EXIT2 = _script("import sys; sys.stdin.read(); sys.stderr.write('blocked'); sys.exit(2)\n")
BLOCK = _script('import sys, json; sys.stdin.read(); print(json.dumps({"decision": "block", "reason": "seed"}))\n')
SKIP = _script('import sys, json; sys.stdin.read(); print(json.dumps({"systemMessage": "skipped"}))\n')


class ZX(unittest.TestCase):
    def setUp(self):
        self.saved = (zx.GUARDS, zx.SCAN, zx.REQUIRED)

    def tearDown(self):
        zx.GUARDS, zx.SCAN, zx.REQUIRED = self.saved

    def run_bash(self, guards, scan, cmd="echo visible"):
        zx.GUARDS, zx.SCAN, zx.REQUIRED = guards, scan, set()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = zx.do_bash(cmd, "/tmp", 20)
        return rc, buf.getvalue()

    def test_allow_runs_and_shows(self):
        rc, out = self.run_bash([ALLOW, ALLOW], ALLOW)
        self.assertEqual(rc, 0)
        self.assertIn("visible", out)

    def test_any_deny_denies(self):
        for gs in ([DENY, ALLOW], [ALLOW, DENY], [EXIT2, ALLOW]):
            rc, out = self.run_bash(gs, ALLOW, "touch /tmp/zx-should-not-exist")
            self.assertEqual(rc, 3)
            self.assertFalse(os.path.exists("/tmp/zx-should-not-exist"))

    def test_broken_guard_fails_closed(self):
        for g in (CRASH, JUNK):
            rc, out = self.run_bash([g], ALLOW)
            self.assertEqual(rc, 3, g)

    def test_missing_required_guard_fails_closed(self):
        zx.GUARDS, zx.SCAN, zx.REQUIRED = ["/nonexistent/guard.py"], ALLOW, {"/nonexistent/guard.py"}
        with redirect_stdout(io.StringIO()):
            self.assertEqual(zx.do_bash("echo x", "/tmp", 20), 3)

    def test_ios_guard_is_required(self):
        self.assertIn(zx.GUARDS[1], self.saved[2])
        self.assertIn(zx.GUARDS[0], self.saved[2])

    def test_scan_block_or_skip_withholds_output(self):
        for s in (BLOCK, SKIP, CRASH, "/nonexistent/scan.py"):
            rc, out = self.run_bash([ALLOW], s)
            self.assertEqual(rc, 4, s)
            self.assertNotIn("visible", out)

    def test_scan_exit2_withholds(self):
        rc, out = self.run_bash([ALLOW], EXIT2)
        self.assertEqual(rc, 4)
        self.assertNotIn("visible", out)

    def test_odd_guard_answers_fail_closed(self):
        odd = [_script("import sys; sys.stdin.read(); print('null')\n"),
               _script('import sys; sys.stdin.read(); print(\'{"continue": false}\')\n'),
               _script('import sys, json; sys.stdin.read(); print(json.dumps({"hookSpecificOutput": '
                       '{"permissionDecision": "block"}}))\n')]
        for g in odd:
            rc, _ = self.run_bash([g], ALLOW)
            self.assertEqual(rc, 3, g)

    def test_paths_resolved_once_from_cwd(self):
        zx.GUARDS, zx.SCAN, zx.REQUIRED = [ALLOW], ALLOW, set()
        d = tempfile.mkdtemp()
        old = os.getcwd()
        os.chdir(d)
        try:
            self.assertEqual(zx._abs("x.txt"), os.path.join(os.path.realpath(d), "x.txt"))
            os.symlink("/etc", os.path.join(d, "link"))
            self.assertEqual(zx._abs("link/hosts"), "/etc/hosts")
        finally:
            os.chdir(old)

    def test_write_checked_with_full_content(self):
        zx.GUARDS, zx.SCAN, zx.REQUIRED = [DENY], ALLOW, set()
        src = _script("content")
        dst = tempfile.mktemp()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(zx.do_write(dst, src), 3)
        self.assertFalse(os.path.exists(dst))
        zx.GUARDS = [ALLOW]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(zx.do_write(dst, src), 0)
        self.assertEqual(open(dst).read(), "content")


if __name__ == "__main__":
    unittest.main()
