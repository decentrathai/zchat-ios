#!/usr/bin/env python3
"""Fail-closed entry for the iOS guard (same contract as the Android guard_entry.py, ZC-2481): any error while
loading guard.py or escaping its main() becomes a deny, so a broken guard never fails open."""
import json
import os
import sys


def _deny(why):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": "ZCHAT iOS guard: " + why}}))
    sys.exit(0)


def run():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import guard  # noqa: PLC0415
    except BaseException as e:  # noqa: BLE001
        _deny("guard.py failed to load (fail-closed): %s" % type(e).__name__)
    try:
        rc = guard.main()
    except BaseException as e:  # noqa: BLE001
        _deny("guard crashed (fail-closed): %s" % type(e).__name__)
    sys.exit(rc or 0)


if __name__ == "__main__":
    run()
