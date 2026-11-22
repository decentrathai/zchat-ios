"""Every tool goes past the guards (Fable research, 22 Nov 2026): the PreToolUse matcher in .claude/settings.json must
cover Glob, NotebookEdit, Agent, WebFetch and MCP tools, not only Bash|Edit|Write|MultiEdit|Read|Grep."""
import json
import os
import sys
import unittest

QA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(os.path.dirname(QA))
sys.path.insert(0, QA)
sys.path.insert(0, os.path.join(QA, "hooks"))
import canary  # noqa: E402
import guard  # noqa: E402

TOOLS = ["Bash", "Read", "Write", "Edit", "MultiEdit", "Grep", "Glob", "NotebookEdit", "Agent", "WebFetch",
         "WebSearch", "mcp__drive__create_file", "SomeFutureTool"]


class Matcher(unittest.TestCase):
    def test_matcher_semantics(self):
        self.assertTrue(canary.matches("*", "Glob"))
        self.assertTrue(canary.matches("", "Glob"))
        self.assertTrue(canary.matches("Bash|Read", "Read"))
        self.assertFalse(canary.matches("Bash|Read", "Glob"))

    def test_both_guards_see_every_tool(self):
        hooks = canary.hooks(os.path.join(ROOT, ".claude", "settings.json"))
        for tool in TOOLS:
            with self.subTest(tool=tool):
                seen = [cmd for m, cmd in hooks if canary.matches(m, tool)]
                self.assertTrue(any("zchat-android/tools/qa/hooks/guard_entry.py" in c for c in seen))
                self.assertTrue(any("zchat-ios/tools/qa/hooks/guard_entry.py" in c for c in seen))

    def test_canaries_include_the_new_tools(self):
        tools = {t for _, t, _ in canary.MUST_DENY}
        self.assertIn("NotebookEdit", tools)
        self.assertIn("Glob", tools)


class GlobTool(unittest.TestCase):
    def test_glob_for_signing_files_denied(self):
        for ti in [{"pattern": "**/AuthKey_*.p8"}, {"pattern": "*.p12", "path": "/home/yourt/zchat-ios"},
                   {"pattern": "*", "path": "/home/yourt/zchat-ios/fastlane/keys"}]:
            with self.subTest(ti=ti):
                self.assertIsNotNone(guard.decide({"tool_name": "Glob", "tool_input": ti,
                                                   "cwd": "/home/yourt/zchat-ios"}))

    def test_plain_glob_allowed(self):
        self.assertIsNone(guard.decide({"tool_name": "Glob", "tool_input": {"pattern": "**/*.swift"},
                                        "cwd": "/home/yourt/zchat-ios"}))

    def test_notebook_edit_into_android_denied(self):
        self.assertIsNotNone(guard.decide({"tool_name": "NotebookEdit", "cwd": "/home/yourt/zchat-ios",
                                           "tool_input": {"notebook_path": "/home/yourt/zchat-android/a.ipynb",
                                                          "new_source": "x"}}))


if __name__ == "__main__":
    unittest.main()
