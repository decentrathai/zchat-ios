"""WI-9 second review (Fable, v2): the origin allowance must check what git will really write, not only the shape of
the command. A planted .git/commondir or a symlinked config redirects `git remote add` into another repo; a missing
.git makes git walk up to a parent. Shell start files and git/gh config files are not written by the agent (they can
set GIT_DIR, aliases, url rewrites); git config includes are refused; the hook's own cwd is required."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

H = guard.HOME


def _write(p, text=""):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


class TreeState(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.ios_git = os.path.join(self.d, "ios", ".git")
        _write(os.path.join(self.ios_git, "config"), "[core]\n\tbare = false\n")
        self.lanes = os.path.join(self.d, "wt")

    def ok(self, tree):
        return guard._wi9_tree_ok(tree, ios_git=self.ios_git, lane_root=self.lanes)

    def repo(self, name="t"):
        t = os.path.join(self.d, name)
        _write(os.path.join(t, ".git", "config"), "[core]\n")
        return t

    def test_plain_repo_ok(self):
        self.assertTrue(self.ok(self.repo()))

    def test_commondir_planted(self):
        t = self.repo()
        _write(os.path.join(t, ".git", "commondir"), "/elsewhere/.git\n")
        self.assertFalse(self.ok(t))

    def test_config_symlink(self):
        t = self.repo()
        os.remove(os.path.join(t, ".git", "config"))
        os.symlink(os.path.join(self.ios_git, "config"), os.path.join(t, ".git", "config"))
        self.assertFalse(self.ok(t))

    def test_config_include(self):
        t = self.repo()
        _write(os.path.join(t, ".git", "config"), "[core]\n[Include]\n\tpath = /tmp/x\n")
        self.assertFalse(self.ok(t))
        _write(os.path.join(t, ".git", "config"), '[includeIf "gitdir:/"]\n\tpath = /tmp/x\n')
        self.assertFalse(self.ok(t))

    def test_no_git_or_no_config_or_missing_tree(self):
        t = os.path.join(self.d, "bare")
        os.makedirs(t)
        self.assertFalse(self.ok(t))
        os.makedirs(os.path.join(t, ".git"))
        self.assertFalse(self.ok(t))
        self.assertFalse(self.ok(os.path.join(self.d, "absent")))

    def test_git_symlink_and_tree_symlink(self):
        t = os.path.join(self.d, "s")
        os.makedirs(t)
        os.symlink(self.ios_git, os.path.join(t, ".git"))
        self.assertFalse(self.ok(t))
        link = os.path.join(self.d, "link")
        os.symlink(self.repo("real"), link)
        self.assertFalse(self.ok(link))

    def test_lane(self):
        wd = os.path.join(self.ios_git, "worktrees", "lane1")
        _write(os.path.join(wd, "commondir"), "../..\n")
        lane = os.path.join(self.lanes, "lane1")
        _write(os.path.join(lane, ".git"), "gitdir: %s\n" % wd)
        self.assertTrue(self.ok(lane))
        _write(os.path.join(wd, "commondir"), "/elsewhere/.git\n")
        self.assertFalse(self.ok(lane))

    def test_gitfile_outside_lanes(self):
        wd = os.path.join(self.ios_git, "worktrees", "x")
        _write(os.path.join(wd, "commondir"), "../..\n")
        t = os.path.join(self.d, "notlane")
        _write(os.path.join(t, ".git"), "gitdir: %s\n" % wd)
        self.assertFalse(self.ok(t))


class StartAndConfigFiles(unittest.TestCase):
    def test_file_tools(self):
        for p in (H + "/.bashrc", H + "/.profile", H + "/.bash_profile", H + "/.gitconfig",
                  H + "/.config/git/config", H + "/.config/gh/config.yml"):
            with self.subTest(p=p):
                self.assertIsNotNone(guard.check_file_tool("Write", {"file_path": p, "content": "x"}, H))
                self.assertIsNotNone(guard.check_file_tool("Edit", {"file_path": p}, H))

    def test_bash_writes(self):
        for cmd in ["echo 'export GIT_DIR=/x' >> ~/.bashrc", "printf x | tee -a /home/yourt/.gitconfig",
                    "cp /tmp/a ~/.config/gh/config.yml", "echo x > $HOME/.profile"]:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, "/home/yourt/zchat-ios"))

    def test_reading_is_fine(self):
        self.assertIsNone(guard.check_bash("cat ~/.gitconfig", "/home/yourt/zchat-ios"))

    def test_git_includes(self):
        for cmd in ["git config include.path /tmp/x", "git config --global includeIf.gitdir:/.path /tmp/x",
                    "git -c include.path=/tmp/x status"]:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, "/home/yourt/zchat-ios"))


class HookCwd(unittest.TestCase):
    def test_no_cwd_in_payload_refused(self):
        old = os.environ.get("CLAUDE_PROJECT_DIR")
        os.environ["CLAUDE_PROJECT_DIR"] = "/home/yourt/zchat-ios"
        try:
            why = guard.decide({"tool_name": "Bash", "tool_input": {
                "command": "git remote add origin https://github.com/decentrathai/zchat-ios.git"}})
        finally:
            if old is None:
                os.environ.pop("CLAUDE_PROJECT_DIR")
            else:
                os.environ["CLAUDE_PROJECT_DIR"] = old
        self.assertIsNotNone(why)


if __name__ == "__main__":
    unittest.main()
