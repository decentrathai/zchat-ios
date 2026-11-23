"""WI-9 review findings (Fable ios-reviewer + DeepSeek-Flash via Android, 23 Nov): the private-repo and origin
allowances hold ONLY for one plain command of an exact shape. Shell expansion, flags in other places, git-dir or
work-tree tricks, cd/pushd/popd, env prefixes and aliases must not reach them."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

IOS = "/home/yourt/zchat-ios"
URL = "https://github.com/decentrathai/zchat-ios.git"


class OtherTreesAllowed(unittest.TestCase):
    """Command shape only; these trees need not exist yet. Their on-disk state is test_wi9_tree.py's job."""

    def setUp(self):
        self._real = guard._wi9_tree_ok
        guard._wi9_tree_ok = lambda tree, **kw: True

    def tearDown(self):
        guard._wi9_tree_ok = self._real

    def test_sdk_release_and_lane_trees(self):
        for cwd, cmd in [
            ("/home/yourt/zchat-nu7-sdk/zcash-swift-wallet-sdk",
             "git remote add origin https://github.com/decentrathai/zcash-swift-wallet-sdk-nu7.git"),
            ("/home/yourt/zchat-ios-release", "git remote add origin https://github.com/decentrathai/zchat-ios-release"),
            ("/home/yourt/zchat-ios-wt/lane1", "git remote add origin " + URL),
        ]:
            with self.subTest(cmd=cmd):
                self.assertIsNone(guard.check_bash(cmd, cwd))


class Refused(unittest.TestCase):
    def test_bypasses(self):
        cases = [
            # flags before the subcommand (Fable Important 1)
            (IOS, "gh repo --source=. --push create decentrathai/zchat-ios-x --private"),
            (IOS, "gh repo --template=someone/pub create decentrathai/zchat-ios-x --private"),
            (IOS, "gh --repo x repo create decentrathai/zchat-ios-x --private"),
            # expansion inside the description (Fable Important 2)
            (IOS, "gh repo create decentrathai/zchat-ios-x --private -d $(echo x --public)"),
            (IOS, 'X="x --source=. --push"; gh repo create decentrathai/zchat-ios-x --private -d $X'),
            (IOS, "gh repo create decentrathai/zchat-ios-x --private -d {x,--public}"),
            (IOS, "gh repo create decentrathai/zchat-ios-x --private -d `echo --public`"),
            (IOS, 'gh repo create decentrathai/zchat-ios-x --private -d "$(echo hi)"'),
            # git's idea of the tree differs from the guard's (Fable Important 3)
            ("/tmp", "GIT_DIR=/home/yourt/zchat-android/.git git -C /home/yourt/zchat-ios remote add origin " + URL),
            ("/tmp", "git --git-dir=/home/yourt/zchat-android/.git --work-tree=/home/yourt/zchat-ios remote add "
                     "origin " + URL),
            (IOS, "D=/home/yourt/zchat-andr; cd ${D}oid && git remote add origin " + URL),
            (IOS, "pushd /tmp/other && pushd /home/yourt/zchat-ios && popd && git remote add origin " + URL),
            (IOS, "cd /tmp/other; git remote add origin " + URL),
            (IOS, "true && git remote add origin " + URL),
            (IOS, "bash -c 'git remote add origin %s'" % URL),
            ("/tmp", "git -C /home/yourt/zchat-ios-wt/.. remote add origin " + URL),
            ("/tmp", "git -C /home/yourt/zchat-ios/ remote add origin " + URL),
            ("/tmp", "git -C $D remote add origin " + URL),
            (IOS, "git -c core.sshCommand=x remote add origin " + URL),
            # trailing newline accepted by $ (DeepSeek Normal 1)
            ("/tmp", "git -C '/home/yourt/zchat-ios\n' remote add origin " + URL),
            (IOS + "\n", "git remote add origin " + URL),
            (IOS, "gh repo create 'decentrathai/zchat-ios-x\n' --private"),
            (IOS, "gh repo create decentrathai/zchat-ios-x --private\n"),
            # env prefixes that move gh elsewhere (Fable Normal)
            (IOS, "GH_HOST=other.example gh repo create decentrathai/zchat-ios-x --private"),
            (IOS, "GH_REPO=someone/x gh repo create decentrathai/zchat-ios-x --private"),
            (IOS, "GH_CONFIG_DIR=/tmp/c gh repo create decentrathai/zchat-ios-x --private"),
            # aliases that rename a refused verb (Fable Normal)
            (IOS, "gh alias set rc 'repo create'"),
            (IOS, "gh alias import aliases.yml"),
            (IOS, "git -c alias.r='remote set-url origin https://github.com/someone/pub' r"),
            (IOS, "git config alias.r 'remote set-url origin https://github.com/someone/pub'"),
            (IOS, "git config --global alias.r '!git remote add x y'"),
            # names wider than zchat-ios-<lowercase> (Fable Nit)
            (IOS, "gh repo create decentrathai/zchat-ios--x --private"),
            (IOS, "gh repo create decentrathai/zchat-ios-x- --private"),
        ]
        for cwd, cmd in cases:
            with self.subTest(cwd=cwd, cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, cwd))


if __name__ == "__main__":
    unittest.main()
