"""Instruction files of the iOS harness (PLAN_HARNESS_ROLES_v2 batch A; W-110, W-103, WI-4).

Pins the role agents (models, tools), REVIEW.md, docs/quality/ORCHESTRATION_IOS.md and the CLAUDE.md commands table.
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
AGENTS = os.path.join(ROOT, ".claude", "agents")
ROLES = {  # role: (model, read_only)
    "ios-reproducer": ("sonnet", True),
    "ios-red-test-author": ("opus", False),
    "ios-implementer": ("opus", False),
    "ios-reviewer": ("fable", True),
    "ios-plan-critic": ("fable", True),
}
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}


def read(*rel):
    with open(os.path.join(ROOT, *rel), encoding="utf-8") as fh:
        return fh.read()


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, "no frontmatter"
    out = {}
    for line in m.group(1).splitlines():
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


class RoleAgents(unittest.TestCase):
    def test_every_role_exists_with_its_model_and_tools(self):
        for role, (model, ro) in ROLES.items():
            with self.subTest(role=role):
                text = read(".claude", "agents", role + ".md")
                fm = frontmatter(text)
                self.assertEqual(fm.get("name"), role)
                self.assertEqual(fm.get("model"), model)
                self.assertNotIn("effort", fm)
                tools = {t.strip() for t in fm.get("tools", "").split(",") if t.strip()}
                self.assertTrue(tools, "tools must be listed explicitly")
                self.assertNotIn("Agent", tools)
                self.assertNotIn("Task", tools)
                if ro:
                    self.assertFalse(tools & WRITE_TOOLS, "%s is read-only" % role)
                else:
                    self.assertTrue({"Edit", "Write"} <= tools)
                self.assertIn("BLOCKED", text, "rule 13: stop and report, never route around")
                self.assertIn("AGENTS.md", text)

    def test_no_other_agent_files(self):
        names = sorted(f[:-3] for f in os.listdir(AGENTS) if f.endswith(".md"))
        self.assertEqual(names, sorted(ROLES))

    def test_reviewer_reads_the_head_and_names_the_shas(self):
        text = read(".claude", "agents", "ios-reviewer.md")
        self.assertIn("git show", text)
        self.assertIn("head_sha", text)
        self.assertIn("REVIEW.md", text)


class Review(unittest.TestCase):
    def test_passes_and_important_lines(self):
        text = read("REVIEW.md")
        for head in ("## Pass 1", "## Pass 2", "## Pass 3", "## Severity", "## Output"):
            self.assertIn(head, text)
        self.assertIn("Android 2.13.1 or 2.12.4 peers", text)
        self.assertIn("Parity", text)
        self.assertIn("base_sha", text)
        self.assertIn("head_sha", text)

    def test_test_weakening_is_reported(self):
        text = read("REVIEW.md")
        dont = text.split("## Do not report", 1)[1].split("\n## ", 1)[0]
        self.assertNotRegex(dont.lower(), r"test-line|deleted .*assert|weaken")
        self.assertRegex(text, r"weaken a test")


class Orchestration(unittest.TestCase):
    def test_models_critique_and_evidence(self):
        text = read("docs", "quality", "ORCHESTRATION_IOS.md")
        for word in ("Sonnet", "Opus", "Fable", "W-110", "W-103", "WI-4", "_FABLE_CRITIQUE.md",
                     "ORCHESTRATION_POLICY.md", "--diff-filter=MDR", "merge-base --is-ancestor", "cooperative"):
            self.assertIn(word, text)


class ClaudeMd(unittest.TestCase):
    def test_imports_agents_and_commands_exist(self):
        text = read("CLAUDE.md")
        self.assertIn("@AGENTS.md", text)
        self.assertIn("ORCHESTRATION_IOS.md", text)
        paths = set(re.findall(r"`((?:tools|docs|\.claude)/[\w./-]+)", text))
        self.assertTrue(paths, "the commands table names no tool")
        for p in paths:
            with self.subTest(path=p):
                self.assertTrue(os.path.exists(os.path.join(ROOT, p)), p)


if __name__ == "__main__":
    unittest.main()
