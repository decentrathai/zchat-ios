"""The repo's own git hooks: tools/qa/githooks/commit-msg and pre-commit (plan E, annex A14; IOSP-3).

Fable harness review, 22 Nov 2026: Android's RED rule accepts a free-text [no-red:] and ignores feat(; iOS takes the
strict form. Every case runs in a temp repo with the hooks copied in, no system or global git config, and a temp HOME.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

QA = Path(__file__).resolve().parents[1]


def env_for(tmp):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "SECRET_SCAN", "ZCHAT_"))}
    home = Path(tmp) / "home"
    home.mkdir()
    (home / ".gitconfig").write_text("")
    env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(home / ".gitconfig"),
               GIT_AUTHOR_NAME="T", GIT_AUTHOR_EMAIL="t@test.invalid", GIT_COMMITTER_NAME="T",
               GIT_COMMITTER_EMAIL="t@test.invalid")
    return env


class HookRepo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iosgh-")
        self.env = env_for(self.tmp)
        self.repo = Path(self.tmp) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "dev")
        for sub in ("githooks", "vendor"):
            shutil.copytree(QA / sub, self.repo / "tools/qa" / sub)
        (self.repo / "README.md").write_text("x\n")
        self.git("add", "-A")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "chore: start")
        self.git("config", "core.hooksPath", "tools/qa/githooks")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args, check=True):
        r = subprocess.run(["git", "-C", str(self.repo), *args], env=self.env, capture_output=True, text=True)
        if check and r.returncode:
            raise AssertionError("git %s: %s%s" % (args, r.stdout, r.stderr))
        return r

    def put(self, rel, text):
        f = self.repo / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        self.git("add", "-f", rel)

    def commit(self, msg):
        r = self.git("commit", "-q", "-m", msg, check=False)
        return r.returncode, r.stdout + r.stderr

    def ok(self, msg):
        rc, out = self.commit(msg)
        self.assertEqual(rc, 0, out)
        return self.git("rev-parse", "--short", "HEAD").stdout.strip()

    def blocked(self, msg, says=None):
        rc, out = self.commit(msg)
        self.assertNotEqual(rc, 0, "commit was allowed: %r" % msg)
        self.assertIn("BLOCKED", out)
        if says:
            self.assertIn(says, out)
        return out

    def red(self):
        self.put("tools/qa/tests/test_x.py", "def test_x():\n    assert False\n")
        return self.ok("test(harness): x fails")


HC = "\n\n[harness-change: test]"


class CommitMsg(HookRepo):
    def test_subject_must_be_conventional(self):
        self.put("docs/a.md", "a\n")
        self.blocked("update stuff", says="type(scope)")

    def test_test_only_commit_passes(self):
        self.red()

    def test_test_commit_touching_code_blocked(self):
        self.put("tools/qa/tests/test_y.py", "def test_y():\n    assert False\n")
        self.put("tools/qa/y.py", "x = 1\n")
        self.blocked("test(harness): y" + HC, says="test(")

    def test_feat_without_red_blocked(self):
        self.put("tools/qa/y.py", "x = 1\n")
        self.blocked("feat(harness): y" + HC, says="[red:")

    def test_feat_with_red_passes(self):
        sha = self.red()
        self.put("tools/qa/y.py", "x = 1\n")
        self.ok("feat(harness): y [red:%s]%s" % (sha, HC))

    def test_no_red_escape_not_accepted(self):
        self.put("tools/qa/y.py", "x = 1\n")
        self.blocked("fix(harness): y [no-red: docs only change]" + HC)

    def test_red_that_touches_code_blocked(self):
        self.put("tools/qa/tests/test_z.py", "def test_z():\n    assert False\n")
        self.put("tools/qa/z.py", "x = 1\n")
        sha = self.ok("chore(harness): mixed" + HC)
        self.put("tools/qa/y.py", "x = 2\n")
        self.blocked("feat(harness): y [red:%s]%s" % (sha, HC), says="only test")

    def test_red_not_an_ancestor_blocked(self):
        self.git("checkout", "-q", "-b", "side")
        sha = self.red()
        self.git("checkout", "-q", "dev")
        self.put("tools/qa/y.py", "x = 1\n")
        self.blocked("feat(harness): y [red:%s]%s" % (sha, HC), says="ancestor")

    def test_red_must_be_a_test_commit(self):
        self.put("tools/qa/tests/test_x.py", "def test_x():\n    assert False\n")
        sha = self.ok("chore(harness): add a test" + HC)
        self.put("tools/qa/y.py", "x = 1\n")
        self.blocked("fix(harness): y [red:%s]%s" % (sha, HC), says="test(")

    def test_unknown_red_blocked(self):
        self.put("tools/qa/y.py", "x = 1\n")
        self.blocked("fix(harness): y [red:deadbeef1]" + HC)

    def test_harness_change_tag_required(self):
        sha = self.red()
        self.put("tools/qa/y.py", "x = 1\n")
        self.blocked("feat(harness): y [red:%s]" % sha, says="[harness-change:")
        self.put(".claude/settings.json", "{}\n")
        self.blocked("chore(harness): settings", says="[harness-change:")

    def test_removed_assertion_needs_tag(self):
        self.put("tools/qa/tests/test_w.py", "def test_w():\n    assert 1 == 1\n    assert 2 == 2\n")
        self.ok("test(harness): w")
        self.put("tools/qa/tests/test_w.py", "def test_w():\n    assert 1 == 1\n")
        self.blocked("test(harness): w smaller", says="[test-change-ok:")
        self.ok("test(harness): w smaller\n\n[test-change-ok: the second case duplicated the first]")

    def test_short_test_change_reason_blocked(self):
        self.put("tools/qa/tests/test_w.py", "def test_w():\n    assert 1 == 1\n    assert 2 == 2\n")
        self.ok("test(harness): w")
        self.put("tools/qa/tests/test_w.py", "def test_w():\n    assert 1 == 1\n")
        self.blocked("test(harness): w smaller\n\n[test-change-ok: dup]")

    def test_deleted_test_file_needs_tag(self):
        self.red()
        self.git("rm", "-q", "tools/qa/tests/test_x.py")
        self.blocked("test(harness): drop x", says="[test-change-ok:")

    def test_added_skip_needs_tag(self):
        for body in ["@Test(.disabled()) func a() {}\n", "func testA() throws { throw XCTSkip() }\n",
                     "withKnownIssue { #expect(false) }\n", "@unittest.skip('later')\ndef test_a(): pass\n"]:
            with self.subTest(body=body):
                self.put("Packages/ZChatCore/Tests/ZChatCoreTests/A.swift", body)
                self.blocked("test(core): a", says="[test-change-ok:")
                self.git("reset", "-q", "--hard")

    def test_product_path_blocked_until_parity_check_exists(self):
        for path in ["Packages/ZChatCore/Sources/ZChatCore/A.swift", "App/Sources/A.swift", "project.yml",
                     "Packages/ZChatCore/Package.swift"]:
            with self.subTest(path=path):
                self.put(path, "x\n")
                self.blocked("refactor(core): a\n\nParity: n/a — pure rename, no behaviour change",
                             says="parity.py check-commit")
                self.git("reset", "-q", "--hard")

    def test_docs_pass(self):
        self.put("docs/a.md", "a\n")
        self.ok("docs: a")


class PreCommit(HookRepo):
    def test_main_and_master_refused(self):
        for b in ("main", "master"):
            with self.subTest(branch=b):
                self.git("checkout", "-q", "-B", b)
                self.put("docs/%s.md" % b, "a\n")
                self.blocked("docs: a", says="branch")

    def test_project_and_signing_files_refused(self):
        for path in ["App.xcodeproj/project.pbxproj", "Sign/AuthKey_ABC123.p8", "Sign/dist.p12",
                     "Sign/app.mobileprovision", "Sign/dev.cer", ".env", "fastlane/.env.default"]:
            with self.subTest(path=path):
                self.put(path, "x\n")
                self.blocked("docs: a", says=path.split("/")[-1])
                self.git("reset", "-q", "--hard")
                self.git("clean", "-qfdx")

    def test_secret_in_staged_lines_refused_and_never_printed(self):
        token = "gh" + "p_" + "Q7x" * 12
        self.put("docs/a.md", "token = %s\n" % token)
        out = self.blocked("docs: a", says="secret")
        self.assertNotIn(token, out)
        self.assertNotIn(token[:10], out)

    def test_changed_vendored_file_refused(self):
        f = self.repo / "tools/qa/vendor/secret_scan.py"
        f.write_text(f.read_text() + "\n# weakened\n")
        self.put("docs/a.md", "a\n")
        self.blocked("docs: a", says="VENDORED.lock")

    def test_missing_scanner_refused(self):
        (self.repo / "tools/qa/vendor/secret_scan.py").unlink()
        self.put("docs/a.md", "a\n")
        self.blocked("docs: a", says="secret_scan.py")

    def test_clean_commit_passes(self):
        self.put("docs/a.md", "plain text\n")
        self.ok("docs: a")


if __name__ == "__main__":
    unittest.main()
