"""Free-tier CI rule. Owner, 23 Nov 2026: "Avoid additional charges from GitHub ... Change it in the next attempts."
IOSP-16: pushing the SDK fork with upstream's .github started 16 Dependabot PRs and ~190 macOS minutes (10x rate) in
one afternoon. From now on a push is refused while the pushed tree holds a workflow that can spend more than a short
Linux run: every job on a GitHub-hosted ubuntu runner, written on one line, with its own timeout-minutes of at most
30; no schedule or workflow_run trigger, no matrix, no reusable or self-hosted runner, and no dependabot file."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

GOOD = """name: ok
on:
  push:
    branches: [dev]
jobs:
  one:
    runs-on: ubuntu-24.04
    timeout-minutes: 12
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
        timeout-minutes: 5
  two:
    runs-on: "ubuntu-latest"
    timeout-minutes: 30
    steps:
      - run: echo two
"""

BAD = {
    "macos runner": GOOD.replace("runs-on: ubuntu-24.04", "runs-on: macos-15"),
    "windows runner": GOOD.replace("runs-on: ubuntu-24.04", "runs-on: windows-latest"),
    "self-hosted runner": GOOD.replace("runs-on: ubuntu-24.04", "runs-on: [self-hosted, linux]"),
    "larger runner": GOOD.replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-24.04-16core"),
    "runner from an expression": GOOD.replace("runs-on: ubuntu-24.04", "runs-on: ${{ matrix.os }}"),
    "runner on the next lines": GOOD.replace("runs-on: ubuntu-24.04", "runs-on:\n      - ubuntu-24.04"),
    "job without timeout": GOOD.replace("    timeout-minutes: 30\n", ""),
    "timeout only on a step": GOOD.replace("    timeout-minutes: 12\n", ""),
    "timeout over 30": GOOD.replace("timeout-minutes: 30", "timeout-minutes: 45"),
    "timeout from an expression": GOOD.replace("timeout-minutes: 30", "timeout-minutes: ${{ inputs.t }}"),
    "job without runs-on": GOOD.replace('    runs-on: "ubuntu-latest"\n', ""),
    "schedule trigger": GOOD.replace("on:\n", "on:\n  schedule:\n    - cron: '0 * * * *'\n"),
    "workflow_run trigger": GOOD.replace("on:\n", "on:\n  workflow_run:\n    workflows: [x]\n"),
    "matrix": GOOD.replace("    timeout-minutes: 12\n", "    timeout-minutes: 12\n    strategy:\n      matrix:\n"
                                                         "        n: [1, 2, 3]\n"),
    "reusable workflow job": GOOD + "  three:\n    uses: ./.github/workflows/other.yml\n",
    "flow-style jobs": "on: push\njobs: {a: {runs-on: macos-15}}\n",
}


class WorkflowText(unittest.TestCase):
    def test_good_workflow_passes(self):
        self.assertIsNone(guard.workflow_cost_problem("ok.yml", GOOD))

    def test_costly_shapes_refused(self):
        for why, text in BAD.items():
            with self.subTest(why=why):
                self.assertIsNotNone(guard.workflow_cost_problem("bad.yml", text))

    def test_this_repo_obeys_the_rule(self):
        self.assertIsNone(guard.tree_cost_problem(REPO))


class PushGate(unittest.TestCase):
    def setUp(self):
        self.tree = tempfile.mkdtemp(prefix="cicost-")
        os.makedirs(os.path.join(self.tree, ".github", "workflows"))
        os.makedirs(os.path.join(self.tree, ".git"))
        self.wf = os.path.join(self.tree, ".github", "workflows", "ci.yml")
        with open(self.wf, "w") as f:
            f.write(GOOD)

    def tearDown(self):
        shutil.rmtree(self.tree, ignore_errors=True)

    def push(self, cmd="git push origin dev", cwd=None):
        return guard.check_bash(cmd, cwd or self.tree)

    def test_good_tree_push_allowed(self):
        self.assertIsNone(self.push())
        self.assertIsNone(self.push("git -C %s push -u origin dev" % self.tree, "/tmp"))

    def test_costly_workflow_blocks_push(self):
        with open(self.wf, "w") as f:
            f.write(BAD["macos runner"])
        for cmd, cwd in [("git push origin dev", self.tree), ("git -C %s push origin dev" % self.tree, "/tmp"),
                         ("git push --all origin", self.tree)]:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(self.push(cmd, cwd))

    def test_yaml_extension_and_dependabot(self):
        os.remove(self.wf)
        with open(os.path.join(self.tree, ".github", "workflows", "b.yaml"), "w") as f:
            f.write(BAD["schedule trigger"])
        self.assertIsNotNone(self.push())
        os.remove(os.path.join(self.tree, ".github", "workflows", "b.yaml"))
        self.assertIsNone(self.push())
        for name in ("dependabot.yml", "dependabot.yaml"):
            p = os.path.join(self.tree, ".github", name)
            with open(p, "w") as f:
                f.write("version: 2\n")
            with self.subTest(name=name):
                self.assertIsNotNone(self.push())
            os.remove(p)

    def test_unreadable_workflow_dir_fails_closed(self):
        os.remove(self.wf)
        os.rmdir(os.path.join(self.tree, ".github", "workflows"))
        with open(os.path.join(self.tree, ".github", "workflows"), "w") as f:
            f.write("not a dir")
        self.assertIsNotNone(self.push())


if __name__ == "__main__":
    unittest.main()
