"""WI-9: the iOS session creates its own PRIVATE GitHub repos and points its own trees at them (rule 13: owner's go
in WI-9 plus a second-family review). Everything else about repos and remotes stays refused."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

IOS = "/home/yourt/zchat-ios"
SPEC = "/home/yourt/zchat-spec"


class RepoCreate(unittest.TestCase):
    def test_private_ios_repos_allowed(self):
        for cmd in ['gh repo create decentrathai/zcash-swift-wallet-sdk-nu7 --private',
                    'GH_TOKEN="$T" gh repo create decentrathai/zchat-ios-release --private',
                    'gh repo create decentrathai/zchat-ios-ci --private --description "iOS CI helpers"',
                    'gh repo create decentrathai/zchat-ios --private -d "ZChat for iOS"']:
            with self.subTest(cmd=cmd):
                self.assertIsNone(guard.check_bash(cmd, IOS))

    def test_everything_else_refused(self):
        for cmd in ['gh repo create decentrathai/zchat-ios-x --public',
                    'gh repo create decentrathai/zchat-ios-x',
                    'gh repo create decentrathai/zchat-ios-x --internal',
                    'gh repo create decentrathai/zchat-ios-x --private --public',
                    'gh repo create decentrathai/zchat-ios-x --private --source . --push',
                    'gh repo create decentrathai/zchat-ios-x --private --template decentrathai/zchat-android',
                    'gh repo create decentrathai/other-project --private',
                    'gh repo create someone-else/zchat-ios-x --private',
                    'gh repo create zchat-ios-x --private',
                    'gh repo delete decentrathai/zchat-ios-x --yes',
                    'gh repo edit decentrathai/zchat-ios --visibility public',
                    'gh repo rename x']:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, IOS))


class RemoteAdd(unittest.TestCase):
    def test_own_trees_to_own_repos_allowed(self):
        for cwd, cmd in [(IOS, "git remote add origin https://github.com/decentrathai/zchat-ios.git"),
                         (SPEC, "git remote add origin https://github.com/decentrathai/zchat-spec.git"),
                         ("/tmp", "git -C /home/yourt/zchat-ios remote add origin "
                                  "https://github.com/decentrathai/zchat-ios.git")]:
            with self.subTest(cmd=cmd):
                self.assertIsNone(guard.check_bash(cmd, cwd))

    def test_everything_else_refused(self):
        for cwd, cmd in [(IOS, "git remote add origin https://github.com/decentrathai/zchat-android.git"),
                         (IOS, "git remote add origin https://github.com/someone/zchat-ios.git"),
                         (IOS, "git remote add origin https://user:tok@github.com/decentrathai/zchat-ios.git"),
                         (IOS, "git remote add origin git@github.com:decentrathai/zchat-ios.git"),
                         (IOS, "git remote add upstream https://github.com/decentrathai/zchat-ios.git"),
                         (IOS, "git remote set-url origin https://github.com/decentrathai/zchat-spec.git"),
                         (IOS, "git remote remove origin"),
                         (SPEC, "git remote add origin https://github.com/decentrathai/zchat-ios.git"),
                         ("/home/yourt/zchat-android",
                          "git remote add origin https://github.com/decentrathai/zchat-ios.git"),
                         ("/tmp", "git remote add origin https://github.com/decentrathai/zchat-ios.git")]:
            with self.subTest(cwd=cwd, cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, cwd))


if __name__ == "__main__":
    unittest.main()
