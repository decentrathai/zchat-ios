"""Public repos get GitHub-hosted standard runners free, macOS included (owner 24 Nov 2026: no charge; WI-12 made
zchat-ios, zchat-spec and zcash-swift-wallet-sdk-nu7 public). So a push may carry a macos-NN / macos-latest job only
from a tree whose origin is one of those three; every other rule of test_ci_cost stays (one-line runner, own
timeout <= 30, no schedule, matrix, reusable workflow, dependabot). A private or unknown origin, a larger macOS
runner (-xlarge, -large), and a tree whose origin cannot be read keep the ubuntu-only rule."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

MAC = """name: app-macos
on:
  workflow_dispatch:
  push:
    branches: [dev]
jobs:
  app:
    runs-on: macos-15
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
"""


def tree(origin, wf=MAC, config=True):
    t = tempfile.mkdtemp(prefix="cimac-")
    os.makedirs(os.path.join(t, ".github", "workflows"))
    os.makedirs(os.path.join(t, ".git"))
    if config:
        with open(os.path.join(t, ".git", "config"), "w") as f:
            f.write('[core]\n\tbare = false\n[remote "origin"]\n\turl = %s\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
                    % origin)
    with open(os.path.join(t, ".github", "workflows", "app.yml"), "w") as f:
        f.write(wf)
    return t


class MacOnPublic(unittest.TestCase):
    def setUp(self):
        self.trees = []

    def tearDown(self):
        for t in self.trees:
            shutil.rmtree(t, ignore_errors=True)

    def mk(self, *a, **k):
        t = tree(*a, **k)
        self.trees.append(t)
        return t

    def test_public_origin_may_use_macos(self):
        for url in ("https://github.com/decentrathai/zchat-ios.git", "https://github.com/decentrathai/zchat-ios",
                    "https://github.com/decentrathai/zchat-spec.git",
                    "https://github.com/decentrathai/zcash-swift-wallet-sdk-nu7.git"):
            for runner in ("macos-15", "macos-14", "macos-latest", "macos-26"):
                with self.subTest(url=url, runner=runner):
                    t = self.mk(url, MAC.replace("macos-15", runner))
                    self.assertIsNone(guard.tree_cost_problem(t))
                    self.assertIsNone(guard.check_bash("git push origin dev", t))

    def test_other_origins_stay_ubuntu_only(self):
        for url in ("https://github.com/decentrathai/zchat-ios-release.git",
                    "https://github.com/decentrathai/zchat-android.git",
                    "https://github.com/someone/zchat-ios.git",
                    "https://github.com/decentrathai/zchat-ios.git.evil",
                    "https://evil.example/decentrathai/zchat-ios.git",
                    "git@github.com:decentrathai/zchat-ios-release.git"):
            with self.subTest(url=url):
                t = self.mk(url)
                self.assertIsNotNone(guard.tree_cost_problem(t))
                self.assertIsNotNone(guard.check_bash("git push origin dev", t))

    def test_unreadable_origin_stays_ubuntu_only(self):
        self.assertIsNotNone(guard.tree_cost_problem(self.mk("x", config=False)))

    def test_two_origin_urls_stay_ubuntu_only(self):
        t = self.mk("https://github.com/decentrathai/zchat-ios.git")
        with open(os.path.join(t, ".git", "config"), "a") as f:
            f.write('[remote "origin"]\n\turl = https://github.com/decentrathai/zchat-ios-release.git\n')
        self.assertIsNotNone(guard.tree_cost_problem(t))

    def test_larger_and_other_runners_refused_even_on_public(self):
        pub = "https://github.com/decentrathai/zchat-ios.git"
        for runner in ("macos-15-xlarge", "macos-15-large", "macos-latest-xlarge", "windows-latest",
                       "[self-hosted, macos]", "macos"):
            with self.subTest(runner=runner):
                self.assertIsNotNone(guard.tree_cost_problem(self.mk(pub, MAC.replace("macos-15", runner))))

    def test_other_rules_still_apply_on_public(self):
        pub = "https://github.com/decentrathai/zchat-ios.git"
        for why, wf in {"no timeout": MAC.replace("    timeout-minutes: 30\n", ""),
                        "timeout 45": MAC.replace("timeout-minutes: 30", "timeout-minutes: 45"),
                        "schedule": MAC.replace("on:\n", "on:\n  schedule:\n    - cron: '0 * * * *'\n"),
                        "matrix": MAC.replace("    timeout-minutes: 30\n",
                                              "    timeout-minutes: 30\n    strategy:\n      matrix:\n        n: [1, 2]\n")}.items():
            with self.subTest(why=why):
                self.assertIsNotNone(guard.tree_cost_problem(self.mk(pub, wf)))

    def test_workflow_text_alone_stays_strict(self):
        self.assertIsNotNone(guard.workflow_cost_problem("app.yml", MAC))


if __name__ == "__main__":
    unittest.main()
