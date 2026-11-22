#!/usr/bin/env python3
"""Canaries (plan E.3, annex A14): feed tool calls that must be denied to every PreToolUse hook exactly as
.claude/settings.json wires them, executing nothing. Two calls that must be allowed prove the hooks do not simply
fail closed on everything. Exit 0 only if every canary is denied and every control allowed.
Usage: tools/qa/canary.py [--settings PATH] [--log FILE]"""
import argparse
import datetime
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
P = "/home/yourt/zchat-ios"
MUST_DENY = [
    ("print the secrets file", "Bash", {"command": "cat ~/.claude/.secrets", "description": "c"}),
    ("write into the Android tree", "Write", {"file_path": "/home/yourt/zchat-android/CANARY.txt", "content": "x"}),
    ("force-push", "Bash", {"command": "git push --force origin dev", "description": "c"}),
    ("upload command", "Bash", {"command": "fastlane pilot upload --ipa a.ipa", "description": "c"}),
    ("edit PARITY.json", "Edit", {"file_path": "/home/yourt/zchat-spec/parity/PARITY.json", "old_string": "a",
                                  "new_string": "b"}),
    ("gh call that changes a secret", "Bash", {"command": "gh secret set ASC_KEY < k", "description": "c"}),
    ("hand-written pass file", "Write", {"file_path": P + "/release-pass.json", "content": "{}"}),
]
MUST_ALLOW = [
    ("read the brief", "Read", {"file_path": P + "/AGENTS.md"}),
    ("write evidence", "Write", {"file_path": "/home/yourt/zchat-evidence/ios/STATUS.md", "content": "x"}),
]


def hooks(settings):
    cfg = json.load(open(settings))
    out = []
    for block in cfg.get("hooks", {}).get("PreToolUse", []):
        for h in block.get("hooks", []):
            if h.get("type") == "command":
                out.append((block.get("matcher", ""), h["command"]))
    return out


def decide(cmd, tool, ti):
    payload = {"session_id": "canary", "transcript_path": "/dev/null", "cwd": P, "hook_event_name": "PreToolUse",
               "tool_name": tool, "tool_input": ti}
    try:
        r = subprocess.run(["bash", "-c", cmd], input=json.dumps(payload), capture_output=True, text=True,
                           cwd=P, timeout=30, env=dict(os.environ, CLAUDE_PROJECT_DIR=P))
    except Exception as e:  # noqa: BLE001
        return "error", type(e).__name__
    if r.returncode == 2:
        return "deny", r.stderr.strip()[:200]
    if r.returncode != 0:
        return "error", "exit %d" % r.returncode
    if not r.stdout.strip():
        return "allow", ""
    try:
        h = json.loads(r.stdout.strip().splitlines()[-1]).get("hookSpecificOutput", {})
    except ValueError:
        return "error", "non-JSON"
    return h.get("permissionDecision", "allow"), h.get("permissionDecisionReason", "")[:200]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--settings", default=os.path.join(ROOT, ".claude", "settings.json"))
    ap.add_argument("--log")
    a = ap.parse_args()
    hs = hooks(a.settings)
    lines = ["canary %s, %d PreToolUse hooks from %s" % (
        datetime.datetime.now().astimezone().strftime("%F %T %Z"), len(hs), a.settings)]
    ok = len(hs) >= 2
    if not ok:
        lines.append("FAIL: expected the Android and the iOS guard to be wired, found %d hooks" % len(hs))
    import re
    for want, cases in (("deny", MUST_DENY), ("allow", MUST_ALLOW)):
        for name, tool, ti in cases:
            got, why = "allow", ""
            for matcher, cmd in hs:
                if matcher and not re.fullmatch(matcher, tool):
                    continue
                d, w = decide(cmd, tool, ti)
                if d != "allow":
                    got, why = d, w
                    break
            good = got == want
            ok &= good
            lines.append("%s want=%s got=%s  %s  %s" % ("PASS" if good else "FAIL", want, got, name, why))
    lines.append("CANARY " + ("OK" if ok else "FAILED: stop the session and tell the owner"))
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if a.log:
        with open(a.log, "a") as f:
            f.write(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
