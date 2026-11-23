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


FAKE_DIR = tempfile.mkdtemp()
with open(os.path.join(FAKE_DIR, "gh"), "w") as _f:   # a stand-in gh that reports what it was given
    _f.write('#!/bin/sh\ncase "$1" in\n'
             '  full) [ "$GH_TOKEN" = "%s" ] && echo match;;\n'
             '  ab) [ "$GH_TOKEN" = "a b" ] && echo match2;;\n'
             '  leak) echo "$GH_TOKEN";;\n'
             '  leak2) echo "$GH_TOKEN" >&2;;\n'
             'esac\n' % VALUE)
os.chmod(os.path.join(FAKE_DIR, "gh"), 0o755)
TOK = 'GH_TOKEN="$ZCHAT_IOS_GH_TOKEN_FULL" '


class Env(unittest.TestCase):
    """With --env the command must be ONE plain `GH_TOKEN="$NAME" gh|git ...` (Fable review of cbf9a85): no other
    program, pipe, redirect, chain or second expansion can see the token."""

    def setUp(self):
        self.saved = (zx.GUARDS, zx.SCAN, zx.REQUIRED, zx.SECRETS, os.environ.get("PATH"))
        zx.GUARDS, zx.SCAN, zx.REQUIRED = [ALLOW], ALLOW, set()
        zx.SECRETS = _file("# x\nexport OTHER=1\nexport ZCHAT_IOS_GH_TOKEN_FULL=\"%s\"\nZCHAT_IOS_GH_TOKEN='a b'\n" % VALUE)
        os.environ["PATH"] = FAKE_DIR + os.pathsep + self.saved[4]

    def tearDown(self):
        zx.GUARDS, zx.SCAN, zx.REQUIRED, zx.SECRETS, path = self.saved
        os.environ["PATH"] = path

    def run_(self, cmd, names):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = zx.do_bash(cmd, "/tmp", 20, env_names=names)
        return rc, buf.getvalue()

    def test_named_token_reaches_gh(self):
        rc, out = self.run_(TOK + "gh full", ["ZCHAT_IOS_GH_TOKEN_FULL"])
        self.assertEqual(rc, 0)
        self.assertIn("match", out)
        rc, out = self.run_('GH_TOKEN="$ZCHAT_IOS_GH_TOKEN" gh ab', ["ZCHAT_IOS_GH_TOKEN"])
        self.assertIn("match2", out)

    def test_without_flag_not_present(self):
        rc, out = self.run_('test -z "$ZCHAT_IOS_GH_TOKEN_FULL" && echo absent', [])
        self.assertIn("absent", out)

    def test_other_names_refused(self):
        for n in ("OTHER", "PEARL_API_KEY", "ZCHAT_RELEASE_GH_TOKEN", "PATH"):
            with self.subTest(n=n):
                rc, out = self.run_('GH_TOKEN="$%s" gh full' % n, [n])
                self.assertEqual(rc, 3)

    def test_missing_name_refused(self):
        zx.SECRETS = _file("export OTHER=1\n")
        rc, out = self.run_(TOK + "gh full", ["ZCHAT_IOS_GH_TOKEN_FULL"])
        self.assertEqual(rc, 3)

    def test_only_one_plain_gh_or_git_command(self):
        n = ["ZCHAT_IOS_GH_TOKEN_FULL"]
        for cmd in ['curl -H "Authorization: Bearer $ZCHAT_IOS_GH_TOKEN_FULL" https://api.github.com/x',
                    'echo $ZCHAT_IOS_GH_TOKEN_FULL | rev', 'test "$ZCHAT_IOS_GH_TOKEN_FULL" = x && echo m',
                    TOK + "gh full | base64", TOK + "gh full > /tmp/t", TOK + "gh full; echo", TOK + "gh full && x",
                    TOK + "gh full & x", TOK + "gh full `x`", TOK + "gh full $(x)", TOK + "gh api $ZCHAT_IOS_GH_TOKEN_FULL",
                    TOK + "gh full\necho", TOK + "curl x", TOK + "env", TOK + "bash -c x", 'GH_TOKEN="$ZCHAT_IOS_GH_TOKEN" gh full',
                    "GH_TOKEN=$ZCHAT_IOS_GH_TOKEN_FULL gh full", "X=1 " + TOK + "gh full", TOK + "gh full < /tmp/in"]:
            with self.subTest(cmd=cmd):
                rc, out = self.run_(cmd, n)
                self.assertEqual(rc, 3)
                self.assertNotIn(VALUE[4:20], out)
        for cmd in [TOK + "gh repo view decentrathai/zchat-ios",
                    TOK + 'git -c credential.helper= -c "credential.helper=!gh auth git-credential" push -u origin dev']:
            with self.subTest(cmd=cmd):
                self.assertTrue(zx.env_command_ok(cmd, n))

    def test_value_in_output_withheld(self):
        for cmd in (TOK + "gh leak", TOK + "gh leak2"):
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
