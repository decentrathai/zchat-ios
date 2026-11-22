#!/usr/bin/env python3
"""zx: guarded tool calls for a ZChat iOS session whose harness has no hooks (WI-2).

The owner runs the iOS orchestrator from a Claude Code desktop session on Windows, where the hooks in
zchat-ios/.claude/settings.json are not loaded. Every action that session takes in WSL goes through this
file instead: the call is shown to each guard as a PreToolUse payload, runs only if every guard allows it,
and its output is shown to output_scan.py as a PostToolUse payload before anyone sees it.

Fail closed: a guard that exits non-zero, times out, or prints something that is not JSON is a deny. Empty
output with exit 0 is an allow (the Claude Code hook contract). An output scan that blocks, errors or skips
withholds the output and prints only the reason.

Usage (paths are WSL paths):
  zx.py bash  '<command>'            [--cwd DIR] [--timeout S]
  zx.py bashf <script-file>          [--cwd DIR] [--timeout S]   (the file's text is the command)
  zx.py read  <path> [--offset N] [--limit N]
  zx.py write <path> --from <file>                               (the full new content is checked)
  zx.py edit  <path> --old <file> --new <file> [--all]
Exit: 0 ran, 3 denied by a guard, 4 output withheld, other = the command's own exit code.
"""
import argparse
import json
import os
import subprocess
import sys

HOME = "/home/yourt"
PROJECT = HOME + "/zchat-ios"
GUARDS = [HOME + "/zchat-android/tools/qa/hooks/guard_entry.py",   # the Android guard: always, first
          PROJECT + "/tools/qa/hooks/guard_entry.py"]               # the iOS guard, once it exists
SCAN = HOME + "/zchat-android/tools/qa/hooks/output_scan.py"
REQUIRED = {GUARDS[0], GUARDS[1], SCAN}                             # the iOS guard exists since 800b911
MAX_OUT = 60000


def _payload(event, tool, tool_input, cwd, response=None):
    p = {"session_id": "zx-wi2", "transcript_path": "/dev/null", "cwd": cwd, "hook_event_name": event,
         "tool_name": tool, "tool_input": tool_input}
    if response is not None:
        p["tool_response"] = response
    return p


def _hook(script, payload, cwd):
    """(ok, decision_json_or_None, why). ok False means fail closed."""
    env = dict(os.environ, CLAUDE_PROJECT_DIR=PROJECT)
    try:
        r = subprocess.run(["python3", script], input=json.dumps(payload), capture_output=True, text=True,
                           cwd=cwd if os.path.isdir(cwd) else PROJECT, env=env, timeout=30)
    except Exception as e:  # noqa: BLE001
        return False, None, "hook %s did not run: %s" % (os.path.basename(script), type(e).__name__)
    if r.returncode == 2:
        return True, {"deny": (r.stderr or "exit 2")[:500]}, ""
    if r.returncode != 0:
        return False, None, "hook %s exited %d (fail-closed)" % (script, r.returncode)
    out = r.stdout.strip()
    if not out:
        return True, None, ""
    try:
        return True, json.loads(out.splitlines()[-1]), ""
    except ValueError:
        return False, None, "hook %s printed non-JSON (fail-closed)" % script


def guard(tool, tool_input, cwd):
    """None if every guard allows, else the reason."""
    for g in GUARDS:
        if not os.path.exists(g):
            if g in REQUIRED:
                return "required guard missing: " + g
            continue
        ok, d, why = _hook(g, _payload("PreToolUse", tool, tool_input, cwd), cwd)
        if not ok:
            return why
        if d is None:
            continue
        if "deny" in d:
            return d["deny"]
        h = d.get("hookSpecificOutput") or {}
        dec = h.get("permissionDecision")
        if dec in ("deny", "ask"):
            return "%s (%s): %s" % (os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(g))))), dec, h.get("permissionDecisionReason", ""))
        if d.get("decision") == "block":
            return d.get("reason", "blocked")
    return None


def scan(tool, tool_input, cwd, response):
    """None if the output may be shown, else the reason it is withheld."""
    if not os.path.exists(SCAN):
        return "output scan missing (fail-closed)"
    ok, d, why = _hook(SCAN, _payload("PostToolUse", tool, tool_input, cwd, response), cwd)
    if not ok:
        return why
    if d is None:
        return None
    if d.get("decision") == "block":
        return "output scan: " + str(d.get("reason", ""))[:800]
    if "systemMessage" in d:
        return "output scan skipped the output (fail-closed): " + str(d["systemMessage"])[:300]
    return None


def emit(tool, tool_input, cwd, response, text):
    why = scan(tool, tool_input, cwd, response)
    if why:
        print("ZX WITHHELD: " + why)
        return 4
    if len(text) > MAX_OUT:
        text = text[:MAX_OUT] + "\n[zx: output cut at %d characters]\n" % MAX_OUT
    sys.stdout.write(text)
    return 0


def do_bash(cmd, cwd, timeout):
    ti = {"command": cmd, "description": "zx"}
    why = guard("Bash", ti, cwd)
    if why:
        print("ZX DENIED: " + why)
        return 3
    try:
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, cwd=cwd, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        out, err, rc = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err, rc = "zx: timeout after %ss" % timeout, 124
    text = out + (("\n[stderr]\n" + err) if err.strip() else "") + ("" if rc == 0 else "\n[exit %d]\n" % rc)
    w = emit("Bash", ti, cwd, {"stdout": out, "stderr": err, "interrupted": False}, text)
    return w if w else rc


def do_read(path, offset, limit):
    ti = {"file_path": path}
    if offset:
        ti["offset"] = offset
    if limit:
        ti["limit"] = limit
    why = guard("Read", ti, PROJECT)
    if why:
        print("ZX DENIED: " + why)
        return 3
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        print("zx: cannot read %s: %s" % (path, e))
        return 1
    start = max((offset or 1) - 1, 0)
    sel = lines[start:start + limit] if limit else lines[start:]
    text = "".join("%6d\t%s" % (start + i + 1, ln) for i, ln in enumerate(sel))
    return emit("Read", ti, PROJECT, {"type": "text", "file": {"filePath": path, "content": "".join(sel)}}, text)


def _write_checked(tool, ti, path, content):
    why = guard(tool, ti, PROJECT)
    if why:
        print("ZX DENIED: " + why)
        return 3
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    print("zx: wrote %s (%d bytes)" % (path, len(content.encode())))
    return 0


def do_write(path, src):
    content = open(src, encoding="utf-8", newline="").read().replace("\r\n", "\n")
    return _write_checked("Write", {"file_path": path, "content": content}, path, content)


def do_edit(path, old_f, new_f, all_):
    old = open(old_f, encoding="utf-8", newline="").read().replace("\r\n", "\n")
    new = open(new_f, encoding="utf-8", newline="").read().replace("\r\n", "\n")
    cur = open(path, encoding="utf-8", newline="").read()
    n = cur.count(old)
    if n == 0 or (n > 1 and not all_):
        print("zx: edit refused: old text found %d times in %s" % (n, path))
        return 1
    ti = {"file_path": path, "old_string": old, "new_string": new, "replace_all": bool(all_)}
    return _write_checked("Edit", ti, path, cur.replace(old, new) if all_ else cur.replace(old, new, 1))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="zx")
    sp = ap.add_subparsers(dest="op", required=True)
    for name in ("bash", "bashf"):
        p = sp.add_parser(name)
        p.add_argument("arg")
        p.add_argument("--cwd", default=PROJECT)
        p.add_argument("--timeout", type=int, default=110)
    p = sp.add_parser("read")
    p.add_argument("path")
    p.add_argument("--offset", type=int)
    p.add_argument("--limit", type=int)
    p = sp.add_parser("write")
    p.add_argument("path")
    p.add_argument("--from", dest="src", required=True)
    p = sp.add_parser("edit")
    p.add_argument("path")
    p.add_argument("--old", required=True)
    p.add_argument("--new", required=True)
    p.add_argument("--all", action="store_true")
    a = ap.parse_args(argv)
    if a.op == "bash":
        return do_bash(a.arg, a.cwd, a.timeout)
    if a.op == "bashf":
        return do_bash(open(a.arg, encoding="utf-8").read().replace("\r\n", "\n"), a.cwd, a.timeout)
    if a.op == "read":
        return do_read(a.path, a.offset, a.limit)
    if a.op == "write":
        return do_write(a.path, a.src)
    return do_edit(a.path, a.old, a.new, a.all)


if __name__ == "__main__":
    sys.exit(main())
