"""zx --env: one named iOS GitHub token from the secrets file reaches ONE child command's environment, never argv,
never output (WI-9: wsl.exe expands $VAR and the guard wants `gh repo create` as one exact command, so the shell
cannot source the secrets file in the same command). bashf drops the file's final newline."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import zx  # noqa: E402

VALUE = "ghp_" + "Zx9" * 12


def _file(body, suffix=".txt"):
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    f.write(body)
    f.close()
    return f.name


ALLOW = _file("import sys; sys.stdin.read()\n", ".py")


class Env(unittest.TestCase):
    def setUp(self):
        self.saved = (zx.GUARDS, zx.SCAN, zx.REQUIRED, zx.SECRETS)
        zx.GUARDS, zx.SCAN, zx.REQUIRED = [ALLOW], ALLOW, set()
        zx.SECRETS = _file("# x\nexport OTHER=1\nexport ZCHAT_IOS_GH_TOKEN_FULL=\"%s\"\nZCHAT_IOS_GH_TOKEN='a b'\n" % VALUE)

    def tearDown(self):
        zx.GUARDS, zx.SCAN, zx.REQUIRED, zx.SECRETS = self.saved

    def run_(self, cmd, names):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = zx.do_bash(cmd, "/tmp", 20, env_names=names)
        return rc, buf.getvalue()

    def test_named_token_reaches_the_child(self):
        rc, out = self.run_('test "$ZCHAT_IOS_GH_TOKEN_FULL" = "%s" && echo match' % VALUE,
                            ["ZCHAT_IOS_GH_TOKEN_FULL"])
        self.assertEqual(rc, 0)
        self.assertIn("match", out)
        rc, out = self.run_('test "$ZCHAT_IOS_GH_TOKEN" = "a b" && echo match2', ["ZCHAT_IOS_GH_TOKEN"])
        self.assertIn("match2", out)

    def test_without_flag_not_present(self):
        rc, out = self.run_('test -z "$ZCHAT_IOS_GH_TOKEN_FULL" && echo absent', [])
        self.assertIn("absent", out)

    def test_other_names_refused(self):
        for n in ("OTHER", "PEARL_API_KEY", "ZCHAT_RELEASE_GH_TOKEN", "PATH"):
            with self.subTest(n=n):
                rc, out = self.run_("echo hi", [n])
                self.assertEqual(rc, 3)
                self.assertNotIn("hi", out)

    def test_missing_name_refused(self):
        zx.SECRETS = _file("export OTHER=1\n")
        rc, out = self.run_("echo hi", ["ZCHAT_IOS_GH_TOKEN_FULL"])
        self.assertEqual(rc, 3)

    def test_value_in_output_withheld(self):
        for cmd in ('echo "$ZCHAT_IOS_GH_TOKEN_FULL"', 'echo "$ZCHAT_IOS_GH_TOKEN_FULL" >&2', 'env'):
            with self.subTest(cmd=cmd):
                rc, out = self.run_(cmd, ["ZCHAT_IOS_GH_TOKEN_FULL"])
                self.assertEqual(rc, 4)
                self.assertNotIn(VALUE, out)
                self.assertNotIn(VALUE[4:20], out)


class Bashf(unittest.TestCase):
    def test_final_newline_dropped(self):
        self.assertEqual(zx.script_text(_file("gh repo view x\n")), "gh repo view x")
        self.assertEqual(zx.script_text(_file("a\r\nb\r\n")), "a\nb")


if __name__ == "__main__":
    unittest.main()
