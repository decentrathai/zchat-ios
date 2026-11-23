"""WI-9: the iOS session sets the default branch of its own private repos (zchat-spec got p0-registry by push
order; GitHub never moves it by itself). Only one exact plain command; every other repo PATCH stays refused."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

IOS = "/home/yourt/zchat-ios"


class DefaultBranch(unittest.TestCase):
    def test_allowed(self):
        for cmd in ['GH_TOKEN="$ZCHAT_IOS_GH_TOKEN_FULL" gh api -X PATCH repos/decentrathai/zchat-spec '
                    '-f default_branch=trunk',
                    "gh api -X PATCH repos/decentrathai/zchat-ios -f default_branch=dev",
                    "gh api -X PATCH repos/decentrathai/zchat-ios-release -f default_branch=release/1-0"]:
            with self.subTest(cmd=cmd):
                self.assertIsNone(guard.check_bash(cmd, IOS))

    def test_refused(self):
        for cmd in ["gh api -X PATCH repos/decentrathai/zchat-spec -f private=false",
                    "gh api -X PATCH repos/decentrathai/zchat-spec -f visibility=public",
                    "gh api -X PATCH repos/decentrathai/zchat-spec -f default_branch=trunk -f private=false",
                    "gh api -X PATCH repos/decentrathai/zchat-spec -F default_branch=trunk",
                    "gh api -X PATCH repos/decentrathai/zchat-spec --input body.json",
                    "gh api -X PATCH repos/decentrathai/zchat-android -f default_branch=x",
                    "gh api -X PATCH repos/someone/zchat-spec -f default_branch=x",
                    "gh api -X PATCH repos/decentrathai/zchat-spec -f default_branch=$B",
                    "gh api -X PATCH repos/decentrathai/zchat-spec -f default_branch=trunk; echo",
                    "gh api -X PATCH repos/decentrathai/zchat-spec -f default_branch=trunk\n",
                    "gh api -X PATCH repos/decentrathai/zchat-spec -f default_branch=../x",
                    "GH_HOST=x gh api -X PATCH repos/decentrathai/zchat-spec -f default_branch=trunk",
                    "gh api -X DELETE repos/decentrathai/zchat-spec"]:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, IOS))


if __name__ == "__main__":
    unittest.main()
