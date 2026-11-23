"""The iOS SDK fork tree (plan C.1, FOREIGN_OK) is the iOS session's own: commands naming it by its full path may write
there. The rest of ~/zchat-nu7-sdk (Android's SDK fork) stays another code base. Bug found 23 Nov: MENTION_OK removed
the tree's name but left "/home/yourt/" behind, which then read as naming the whole home folder."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

T = "/home/yourt/zchat-nu7-sdk/zcash-swift-wallet-sdk"


class SdkTree(unittest.TestCase):
    def test_own_tree_writable(self):
        for cwd, cmd in [("/tmp", "rm -rf " + T),
                         ("/tmp", "rm -rf %s/rust/target" % T),
                         ("/tmp", "cargo test --manifest-path %s/rust/Cargo.toml" % T),
                         ("/tmp", "cp /tmp/rng.rs %s/rust/src/rng.rs" % T),
                         ("/tmp", "mkdir -p ~/zchat-nu7-sdk/zcash-swift-wallet-sdk/x"),
                         (T, "cargo check --manifest-path rust/Cargo.toml")]:
            with self.subTest(cmd=cmd):
                self.assertIsNone(guard.check_bash(cmd, cwd))

    def test_android_sdk_and_parent_protected(self):
        for cwd, cmd in [("/tmp", "rm -rf /home/yourt/zchat-nu7-sdk/zcash-android-wallet-sdk"),
                         ("/tmp", "rm -rf /home/yourt/zchat-nu7-sdk"),
                         ("/tmp", "rm -rf %s /home/yourt/zchat-nu7-sdk/maven-repo" % T),
                         ("/tmp", "rm -rf %s/../maven-repo" % T),
                         ("/tmp", "rm -rf %s-x" % T),
                         ("/tmp", "rm -rf /home/yourt/zchat-nu7-sdk/zcash-swift-wallet-sdkx /home/yourt/zchat-android"),
                         ("/tmp", "cp x " + T + " /home/yourt/zchat-android/y")]:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, cwd))


if __name__ == "__main__":
    unittest.main()
