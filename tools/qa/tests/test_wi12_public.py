"""WI-12 (owner, 24 Nov 2026): ZChat iOS is open source like Android; "You have PAT from GitHub ... Do everything by
yourself." The three repos were made public on 24 Nov with the one-shot exact form (34bc6c6). It is done, so the
form is gone again (Fable review: a standing allowance could re-publish a repo the owner later makes private).
Every visibility change, including the old exact form, is refused."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

IOS = "/home/yourt/zchat-ios"
ACK = " --visibility public"


class MakePublic(unittest.TestCase):
    def test_one_shot_form_is_gone(self):
        for repo in ("zchat-ios", "zchat-spec", "zcash-swift-wallet-sdk-nu7"):
            for cmd in ['GH_TOKEN="$ZCHAT_IOS_GH_TOKEN_FULL" gh repo edit decentrathai/' + repo + ACK,
                        "gh repo edit decentrathai/" + repo + ACK]:
                with self.subTest(cmd=cmd):
                    self.assertIsNotNone(guard.check_bash(cmd, IOS))

    def test_refused(self):
        for cmd in ["gh repo edit decentrathai/zchat-ios-release" + ACK,
                    "gh repo edit decentrathai/zchat-ios-x" + ACK,
                    "gh repo edit decentrathai/zchat-android" + ACK,
                    "gh repo edit decentrathai/zcash-android-wallet-sdk-nu7" + ACK,
                    "gh repo edit someone/zchat-ios" + ACK,
                    "gh repo edit zchat-ios" + ACK,
                    "gh repo edit decentrathai/zchat-ios --visibility private",
                    "gh repo edit decentrathai/zchat-ios --visibility internal",
                    "gh repo edit decentrathai/zchat-ios" + ACK + " --default-branch x",
                    "gh repo edit decentrathai/zchat-ios --default-branch x" + ACK,
                    "gh repo edit --visibility public decentrathai/zchat-ios",
                    "gh repo edit decentrathai/zchat-ios" + ACK + "; echo",
                    "gh repo edit decentrathai/zchat-ios" + ACK + "\n",
                    "gh repo edit decentrathai/$R" + ACK,
                    "GH_HOST=x gh repo edit decentrathai/zchat-ios" + ACK,
                    "GH_REPO=decentrathai/zchat-android gh repo edit decentrathai/zchat-ios" + ACK,
                    "gh api -X PATCH repos/decentrathai/zchat-ios -f visibility=public",
                    "gh api -X PATCH repos/decentrathai/zchat-ios -F private=false",
                    "gh repo edit decentrathai/zchat-ios --visibility public --accept-visibility-change-consequences",
                    "gh repo delete decentrathai/zchat-ios --yes",
                    "gh repo edit decentrathai/zchat-ios" + ACK + " ",
                    "gh repo edit decentrathai/zchat-ios" + ACK + "\t",
                    " gh repo edit decentrathai/zchat-ios" + ACK,
                    "gh repo edit -R decentrathai/zchat-ios" + ACK,
                    "gh repo edit decentrathai/zchat-ios --visibility=public",
                    "gh repo edit Decentrathai/ZChat-iOS-Release" + ACK,
                    "gh repo edit decentrathai/ZCHAT-IOS-RELEASE" + ACK,
                    "gh repo edit decentrathai/zchat-ios.git" + ACK,
                    "gh repo edit https://github.com/decentrathai/zchat-android" + ACK,
                    "bash -c 'gh repo edit decentrathai/zchat-ios" + ACK + "'",
                    "XDG_CONFIG_HOME=/tmp/x gh repo edit decentrathai/zchat-ios" + ACK]:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, IOS))

    def test_ambient_bad_env_refuses_the_exact_form(self):
        for k in ("GH_HOST", "GH_REPO", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "GIT_DIR"):
            with self.subTest(env=k):
                old = os.environ.get(k)
                os.environ[k] = "/tmp/elsewhere"
                try:
                    self.assertIsNotNone(guard.check_bash("gh repo edit decentrathai/zchat-ios" + ACK, IOS))
                finally:
                    if old is None:
                        del os.environ[k]
                    else:
                        os.environ[k] = old


if __name__ == "__main__":
    unittest.main()
