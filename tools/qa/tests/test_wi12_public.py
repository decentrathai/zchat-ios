"""WI-12 (owner, 24 Nov 2026): ZChat iOS is open source like Android; "You have PAT from GitHub ... Do everything by
yourself." The iOS session may make exactly its three repos public with one exact plain command each. Everything else
about visibility stays refused: other repos (zchat-ios-release, Android's), private, other flags, the API form."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

IOS = "/home/yourt/zchat-ios"
ACK = " --visibility public --accept-visibility-change-consequences"


class MakePublic(unittest.TestCase):
    def test_allowed(self):
        for repo in ("zchat-ios", "zchat-spec", "zcash-swift-wallet-sdk-nu7"):
            for cmd in ['GH_TOKEN="$ZCHAT_IOS_GH_TOKEN_FULL" gh repo edit decentrathai/' + repo + ACK,
                        "gh repo edit decentrathai/" + repo + ACK]:
                with self.subTest(cmd=cmd):
                    self.assertIsNone(guard.check_bash(cmd, IOS))

    def test_refused(self):
        for cmd in ["gh repo edit decentrathai/zchat-ios-release" + ACK,
                    "gh repo edit decentrathai/zchat-ios-x" + ACK,
                    "gh repo edit decentrathai/zchat-android" + ACK,
                    "gh repo edit decentrathai/zcash-android-wallet-sdk-nu7" + ACK,
                    "gh repo edit someone/zchat-ios" + ACK,
                    "gh repo edit zchat-ios" + ACK,
                    "gh repo edit decentrathai/zchat-ios --visibility private --accept-visibility-change-consequences",
                    "gh repo edit decentrathai/zchat-ios --visibility internal --accept-visibility-change-consequences",
                    "gh repo edit decentrathai/zchat-ios" + ACK + " --default-branch x",
                    "gh repo edit decentrathai/zchat-ios --default-branch x" + ACK,
                    "gh repo edit --visibility public --accept-visibility-change-consequences decentrathai/zchat-ios",
                    "gh repo edit decentrathai/zchat-ios" + ACK + "; echo",
                    "gh repo edit decentrathai/zchat-ios" + ACK + "\n",
                    "gh repo edit decentrathai/$R" + ACK,
                    "GH_HOST=x gh repo edit decentrathai/zchat-ios" + ACK,
                    "GH_REPO=decentrathai/zchat-android gh repo edit decentrathai/zchat-ios" + ACK,
                    "gh api -X PATCH repos/decentrathai/zchat-ios -f visibility=public",
                    "gh api -X PATCH repos/decentrathai/zchat-ios -F private=false",
                    "gh repo edit decentrathai/zchat-ios --visibility public",
                    "gh repo delete decentrathai/zchat-ios --yes"]:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, IOS))


if __name__ == "__main__":
    unittest.main()
