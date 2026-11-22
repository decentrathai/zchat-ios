#!/usr/bin/env python3
"""iOS guard (plan E.3, annex A14). Runs BESIDE the Android guard, never instead of it: a deny from either denies.

The Android guard's general rules (force-push, main/master, secrets file, PINs, seeds, `.git` writes, `git remote add`,
hand-written pass files) are not repeated here. This file adds what only the iOS session needs:
  1. no write into another code base or its settings (Android, its worktrees, backend, QA config, denylist hooks)
  2. no publishing outside the pipeline, no repo made public, no push to a URL, no hook bypass
  3. no GitHub control change (secrets, environments, keys, branch rules, workflow permissions, deployments) or billing
  4. no read or write of Apple signing material
  5. no direct edit of the parity files (only tools/parity.py writes them)
  6. no ssh/scp/rsync/sftp; no AGPL/GPL package (ZODL SDK, libsignal, Slipstream) in Package.swift
  7. no build, test or script run inside ~/zchat-evidence/ios/thirdparty

Floor (AGENTS.md rule 13): groups 1 to 5 are not made narrower without the owner's go and a second-family review.
Limits (plan D.11): a program that writes files by itself (python -c, a script) is not parsed; the range check, the
vendored-file check and `validate` catch what this guard cannot see.
"""
import json
import os
import re
import shlex
import sys

HOME = "/home/yourt"
FOREIGN = [HOME + "/zchat-android", HOME + "/zchat-android-wt", HOME + "/zchat", HOME + "/zchat-worktrees",
           HOME + "/.config/zchat-qa", HOME + "/.config/zchat-denylist", HOME + "/zchat-nu7-sdk"]
FOREIGN_OK = [HOME + "/zchat-nu7-sdk/zcash-swift-wallet-sdk"]          # the iOS SDK fork (plan C.1)
LOCK_OK = re.compile(r"^" + re.escape(HOME) + r"/\.config/zchat-qa/locks/[\w.-]+\.lock$")
THIRDPARTY = HOME + "/zchat-evidence/ios/thirdparty"
PARITY_ROOTS = [HOME + "/zchat-spec/parity", HOME + "/zchat-ios/parity"]
PARITY_WT = re.compile(r"^" + re.escape(HOME) + r"/zchat-ios-wt/[^/]+/parity(/|$)")
SIGNING = re.compile(r"(\.p8|\.p12|\.mobileprovision|\.cer|\.certSigningRequest)$|(^|/)AuthKey_[^/]*$|"
                     r"(^|/)fastlane/\.env[^/]*$", re.I)
BAD_PACKAGES = re.compile(r"zodl|libsignal|slipstream", re.I)

WRITE_ANY = {"rm", "rmdir", "touch", "mkdir", "truncate", "chmod", "chown", "chgrp", "shred", "unlink", "tee",
             "ln", "setfacl", "chattr"}
WRITE_DEST = {"cp", "install", "rsync"}                                  # last path argument is written
GIT_WRITE = {"add", "commit", "checkout", "switch", "reset", "restore", "apply", "am", "merge", "rebase",
             "cherry-pick", "revert", "stash", "push", "pull", "fetch", "tag", "rm", "mv", "clean", "worktree",
             "gc", "prune", "update-ref", "update-index", "notes", "submodule", "init", "replace", "filter-branch",
             "branch", "config", "remote", "lfs", "sparse-checkout", "maintenance", "repack"}
GIT_BRANCH_READ = {"--list", "-l", "-a", "-r", "--show-current", "-v", "-vv", "--contains", "--merged"}
RUNNERS = {"swift", "make", "cmake", "cargo", "npm", "npx", "yarn", "pnpm", "bash", "sh", "zsh", "python",
           "python3", "node", "xcodebuild", "xcrun", "gradle", "ruby", "perl", "pod", "bundle", "fastlane",
           "rustc", "go", "just", "ninja", "meson", "pip", "pip3", "uv", "tuist", "xcodegen"}
SEPARATORS = {";", "&&", "||", "|", "&", "\n", "|&", "(", ")"}
REDIRS = {">", ">>", "&>", "&>>", ">|", "<>"}
GH_CONTROL = re.compile(r"(environments|secrets|/keys\b|deploy[-_]keys|branches/[^ ]*/protection|rulesets|"
                        r"actions/permissions|deployments|pending_deployments|collaborators|/hooks\b|billing|"
                        r"budget|spending|/visibility|/dispatches)", re.I)


# ---------------------------------------------------------------- paths
def _norm(p, cwd):
    p = p.strip()
    if not p:
        return ""
    for h in ("$HOME", "${HOME}"):
        if p.startswith(h):
            p = HOME + p[len(h):]
    if p.startswith("~/") or p == "~":
        p = HOME + p[1:]
    if not p.startswith("/"):
        p = os.path.join(cwd or HOME, p)
    return os.path.normpath(p)


def _under(p, root):
    return p == root or p.startswith(root + "/")


def foreign(p):
    if not p or LOCK_OK.match(p):
        return None
    if any(_under(p, ok) for ok in FOREIGN_OK):
        return None
    for root in FOREIGN:
        if _under(p, root):
            return root
    return None


def parity_file(p):
    return bool(p) and (any(_under(p, r) for r in PARITY_ROOTS) or bool(PARITY_WT.match(p)))


# ---------------------------------------------------------------- bash parsing
def _segments(cmd):
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>")
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        toks = list(lex)
    except ValueError:
        return None
    segs, cur = [], []
    for t in toks:
        if t in SEPARATORS:
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _strip_env(seg):
    i = 0
    while i < len(seg) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i]):
        i += 1
    rest = seg[i:]
    while rest and rest[0] in ("sudo", "env", "nohup", "time", "command", "exec", "nice", "timeout", "stdbuf"):
        rest = rest[1:]
        while rest and (rest[0].startswith("-") or re.match(r"^\d+[smhd]?$", rest[0]) or "=" in rest[0]):
            rest = rest[1:]
    return rest


def _redirect_targets(seg):
    out, args, i = [], [], 0
    while i < len(seg):
        t = seg[i]
        if t in REDIRS or (t.endswith(">") and t.rstrip(">").isdigit()):
            if i + 1 < len(seg):
                nxt = seg[i + 1]
                if nxt.startswith("&") or nxt in (">",):
                    i += 2
                    continue
                out.append(nxt)
            i += 2
            continue
        if t == "<":
            i += 2
            continue
        if re.match(r"^\d*>>?\S+$", t) and not t.startswith(">&"):
            tgt = re.sub(r"^\d*>>?", "", t)
            if not tgt.startswith("&"):
                out.append(tgt)
            i += 1
            continue
        args.append(t)
        i += 1
    return out, args


def _paths(args):
    return [a for a in args if not a.startswith("-")]


def _git_repo_and_sub(args, cwd):
    repo, i = cwd, 1
    while i < len(args):
        a = args[i]
        if a == "-C" and i + 1 < len(args):
            repo = _norm(args[i + 1], repo)
            i += 2
        elif a == "-c" and i + 1 < len(args):
            i += 2
        elif a.startswith("--git-dir=") or a.startswith("--work-tree="):
            repo = _norm(a.split("=", 1)[1], repo)
            i += 1
        elif a.startswith("-"):
            i += 1
        else:
            return repo, a, args[i + 1:]
    return repo, None, []


def check_git(args, cwd, line):
    if "--no-verify" in args or any(a == "-n" for a in args[2:3]) and args[1:2] == ["commit"]:
        return "git --no-verify skips the hooks (A14)"
    for i, a in enumerate(args):
        if a == "-c" and i + 1 < len(args) and args[i + 1].lower().startswith("core.hookspath"):
            return "another core.hooksPath skips the hooks (A14)"
    repo, sub, rest = _git_repo_and_sub(args, cwd)
    if sub == "config":
        low = [r.lower() for r in rest]
        if "core.hookspath" in low and len(_paths(rest)) > 1 or "--unset" in low and "core.hookspath" in low:
            return "changing core.hooksPath is refused (A14)"
    if sub == "remote" and rest[:1] in (["set-url"], ["rename"], ["add"]):
        return "remotes are added and changed by the owner only (plan C.1)"
    if sub == "push" and any(re.match(r"^(https?://|git@|ssh://|git://)", r) for r in rest):
        return "push to a URL instead of a named remote is refused (A14: no push to a public remote)"
    if sub in GIT_WRITE:
        if sub == "branch" and (not rest or all(r in GIT_BRANCH_READ for r in rest)):
            return None
        if sub == "config" and len(_paths(rest)) <= 1 and "--unset" not in rest and "--add" not in rest:
            return None
        if sub == "worktree" and rest[:1] == ["list"]:
            return None
        if sub == "stash" and rest[:1] in (["list"], ["show"]):
            return None
        if sub == "remote" and (not rest or rest[:1] in (["-v"], ["show"], ["get-url"])):
            return None
        root = foreign(repo)
        if root:
            return "git %s in %s writes into another code base (A14); hand a patch over the mailbox" % (sub, root)
        if sub == "worktree" and rest[:1] == ["add"]:
            for p in _paths(rest[1:])[:1]:
                if foreign(_norm(p, repo)):
                    return "a worktree inside another code base is refused (A14)"
    if sub == "clone":
        dest = _paths(rest)[1:2]
        if dest and foreign(_norm(dest[0], cwd)):
            return "clone into another code base is refused (A14)"
    return None


def check_gh(args):
    sub = args[1:3]
    if sub[:1] == ["release"] and sub[1:2] in (["create"], ["upload"], ["edit"], ["delete"]):
        return "gh release is publishing; only release_pipeline.py after a valid pass (A14)"
    if sub[:1] == ["workflow"] and sub[1:2] in (["run"], ["enable"], ["disable"]):
        return "starting or changing a workflow is refused until ci_verify.py exists; paid CI is a spend (WI-1 B8)"
    if sub[:1] == ["run"] and sub[1:2] in (["rerun"],):
        return "a rerun starts paid minutes; refused until ci_verify.py exists (WI-1 B8)"
    if sub[:1] in (["secret"], ["variable"]) and sub[1:2] in (["set"], ["delete"], ["remove"]):
        return "gh %s %s changes a GitHub control (A14)" % tuple(sub)
    if sub[:1] == ["repo"]:
        joined = " ".join(args)
        if sub[1:2] in (["create"], ["edit"], ["delete"], ["rename"], ["archive"], ["fork"]):
            if "--public" in args or "public" in joined or sub[1:2] != ["create"]:
                return "gh repo %s is refused: repos are made and changed by the owner (plan C.1)" % sub[1]
            return "creating a repo needs the owner's go in WAIVERS_IOS.md (B8 is open)"
    if sub[:1] == ["ruleset"] or sub[:1] == ["auth"] and sub[1:2] in (["refresh"], ["token"]):
        return "gh %s is refused (A14)" % sub[0]
    if sub[:1] == ["api"]:
        rest = args[2:]
        method = "GET"
        for i, a in enumerate(rest):
            if a in ("-X", "--method") and i + 1 < len(rest):
                method = rest[i + 1].upper()
            elif a.startswith("--method="):
                method = a.split("=", 1)[1].upper()
            elif a in ("-f", "-F", "--field", "--raw-field", "--input") and method == "GET":
                method = "POST"
        path = " ".join(r for r in rest if not r.startswith("-"))
        if method != "GET" and GH_CONTROL.search(path):
            return "gh api %s on %s changes a GitHub control or billing (A14)" % (method, path[:80])
        if method != "GET" and re.search(r"(/releases|/actions/workflows/.*/dispatches|/actions/runs/.*/rerun)",
                                         path):
            return "gh api %s on %s publishes or starts paid CI (A14)" % (method, path[:80])
    return None


PUBLISH = [
    (re.compile(r"\bfastlane\b.*\b(pilot|deliver|upload_to_testflight|upload_to_app_store|supply|submit)\b"),
     "fastlane upload is publishing; only release_pipeline.py after a valid pass (A14)"),
    (re.compile(r"\baltool\b.*--upload-(app|package)"), "altool upload is publishing (A14)"),
    (re.compile(r"\bxcrun\s+(notarytool|altool)\b.*\bsubmit\b"), "a submit to Apple is publishing (A14)"),
    (re.compile(r"\btransporter\b|\biTMSTransporter\b", re.I), "Transporter upload is publishing (A14)"),
    (re.compile(r"api\.appstoreconnect\.apple\.com"), "App Store Connect API calls go only through the pipeline (A14)"),
    (re.compile(r"\bsecurity\s+(find-generic-password|find-internet-password)\b.*\s-w\b"),
     "printing a keychain password is refused (A14)"),
    (re.compile(r"\bsecurity\s+export\b"), "exporting keychain items is refused (A14)"),
]


def check_bash(cmd, cwd):
    for rx, why in PUBLISH:
        if rx.search(cmd):
            return why
    segs = _segments(cmd)
    if segs is None:
        return "the guard cannot parse this command (unbalanced quotes); fail-closed"
    here = cwd or HOME
    for seg in segs:
        redirs, args = _redirect_targets(seg)
        args = _strip_env(args)
        for r in redirs:
            p = _norm(r, here)
            if p.startswith("/dev/"):
                continue
            root = foreign(p)
            if root:
                return "writing %s writes into another code base (%s); hand a patch over the mailbox" % (r, root)
            if parity_file(p):
                return "parity files are written only by tools/parity.py (plan D.2)"
            if SIGNING.search(p):
                return "writing signing material is refused (A14)"
        if not args:
            continue
        prog = os.path.basename(args[0])
        if prog == "cd":
            here = _norm(args[1], here) if len(args) > 1 else HOME
            continue
        for a in args[1:]:
            if SIGNING.search(a.strip("'\"")) and prog not in ("ls", "find", "git"):
                return "signing material (%s) is never read, copied or printed (A14)" % os.path.basename(a)
        if prog in ("ssh", "scp", "sftp", "mosh") or prog == "rsync" and any(
                re.match(r"^[^/]*[\w.-]+:", a) for a in args[1:]):
            return "no ssh to servers; server work belongs to the backend session (A14)"
        if _under(here, THIRDPARTY) and (prog in RUNNERS or args[0].startswith("./")):
            return "no build, test or script run inside thirdparty (plan C.5)"
        if prog == "git":
            why = check_git(args, here, cmd)
            if why:
                return why
            continue
        if prog == "gh":
            why = check_gh(args)
            if why:
                return why
            continue
        if prog == "flock":
            continue
        targets = []
        if prog in WRITE_ANY:
            targets = _paths(args[1:])
        elif prog == "mv":
            targets = _paths(args[1:])
        elif prog in WRITE_DEST:
            ps = _paths(args[1:])
            targets = ps[-1:]
        elif prog in ("sed", "perl") and any(a == "-i" or a.startswith("-i") or a.startswith("--in-place")
                                             for a in args[1:]):
            targets = _paths(args[1:])[1:] if prog == "sed" else _paths(args[1:])
        elif prog == "dd":
            targets = [a[3:] for a in args[1:] if a.startswith("of=")]
        elif prog == "tar" and any(a in ("-C", "--directory") for a in args):
            i = max(i for i, a in enumerate(args) if a in ("-C", "--directory"))
            if any("x" in a for a in args[1:2]) or "-x" in args or "--extract" in args:
                targets = args[i + 1:i + 2]
        elif prog in ("unzip",) and "-d" in args:
            targets = args[args.index("-d") + 1:args.index("-d") + 2]
        elif prog == "patch":
            targets = [here]
        for t in targets:
            p = _norm(t, here)
            root = foreign(p)
            if root:
                return "%s on %s writes into another code base (%s); hand a patch over the mailbox" % (prog, t, root)
            if parity_file(p):
                return "parity files are written only by tools/parity.py (plan D.2)"
    return None


def check_file_tool(tool, ti, cwd):
    path = ti.get("file_path") or ti.get("notebook_path") or ti.get("path") or ""
    p = _norm(path, cwd) if path else ""
    if tool == "Read" or tool == "Grep":
        if p and SIGNING.search(p):
            return "signing material is never read (A14)"
        return None
    root = foreign(p)
    if root:
        return "writing %s writes into another code base (%s); hand a patch over the mailbox (A14)" % (path, root)
    if parity_file(p):
        return "parity files are written only by tools/parity.py (plan D.2)"
    if SIGNING.search(p):
        return "writing signing material is refused (A14)"
    if os.path.basename(p) == "Package.swift":
        text = ti.get("content") or ti.get("new_string") or ""
        for e in ti.get("edits") or []:
            text += "\n" + str(e.get("new_string", ""))
        m = BAD_PACKAGES.search(text)
        if m:
            return "%s is AGPL/GPL or otherwise refused in the tree (plan A.3, C.5)" % m.group(0)
    return None


def decide(payload):
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or HOME
    if tool == "Bash":
        return check_bash(str(ti.get("command", "")), cwd)
    if tool in ("Read", "Grep", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        return check_file_tool(tool, ti, cwd)
    return None


def deny(why):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": "ZCHAT iOS guard: " + why}}))


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("payload is not an object")
    except ValueError:
        deny("unreadable hook payload (fail-closed)")
        return 0
    try:
        why = decide(payload)
    except Exception as e:  # noqa: BLE001 - fail closed
        deny("guard error %s (fail-closed)" % type(e).__name__)
        return 0
    if why:
        deny(why)
    return 0


if __name__ == "__main__":
    sys.exit(main())
