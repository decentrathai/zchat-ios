#!/usr/bin/env python3
"""iOS guard (plan E.3, annex A14). Runs BESIDE the Android guard, never instead of it: a deny from either denies.

The Android guard's general rules (force-push, main/master, secrets file, PINs, seeds, `.git` writes, `git remote add`,
hand-written pass files) are not repeated here. This file adds what only the iOS session needs:
  1. no write into another code base or its settings (Android, its worktrees, backend, QA config, denylist hooks)
  2. no publishing outside the pipeline, no repo made public, no push to a URL, no hook bypass
  3. no GitHub control change (secrets, variables, environments, keys, branch rules, permissions, deployments) or billing
  4. no read or write of Apple signing material
  5. no direct edit of the parity files (only tools/parity.py writes them)
  6. no ssh/scp/rsync-to-host/sftp; no AGPL/GPL package (ZODL SDK, libsignal, Slipstream) in Package.swift
  7. no build, test or script run inside ~/zchat-evidence/ios/thirdparty

Two layers for rules 1 and 5. (a) Precise checks of what each known writer writes. (b) The MENTION rule: a command whose
text names another code base or a parity file in any form (variable, glob, parent, substitution) may run only programs
that cannot write (READONLY), plus the precisely checked copy tools whose destinations are literal paths. So what (a)
misparses, (b) still stops. Unparseable text fails closed.

Floor (AGENTS.md rule 13): groups 1 to 5 are not made narrower without the owner's go and a second-family review.
Limits (plan D.11): a program file that writes by itself without naming a protected path in the command is not seen; the
range check, the vendored-file check and `validate` catch what this guard cannot.
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
HEAVY = HOME + "/zchat-android/tools/qa/heavy.py"
THIRDPARTY = HOME + "/zchat-evidence/ios/thirdparty"
PARITY_ROOTS = [HOME + "/zchat-spec/parity", HOME + "/zchat-ios/parity"]
PARITY_WT = re.compile(r"^" + re.escape(HOME) + r"/zchat-ios-wt/[^/]+/parity(/|$)")
SIGNING = re.compile(r"(\.p8|\.p12|\.mobileprovision|\.cer|\.certSigningRequest)$|(^|[/:])AuthKey_[^/]*$|"
                     r"(^|[/:])fastlane/\.env[^/]*$|(^|[/:])\.env(\.[\w-]+)?$", re.I)
SIGNING_DIR = re.compile(r"(^|/)fastlane(/(keys|certs|certificates|profiles|match|signing)(/|$)|/?$)", re.I)
BAD_PACKAGES = re.compile(r"zodl|libsignal|slipstream", re.I)

# Text that names a protected place in any spelling. Removed first: the lock files and heavy.py, which are allowed.
MENTION_OK = re.compile(r"(~|\$HOME|\$\{HOME\}|/home/yourt)/\.config/zchat-qa/locks/[\w.-]+\.lock|"
                        r"(~|\$HOME|\$\{HOME\}|/home/yourt)/zchat-android/tools/qa/heavy\.py|"
                        r"(~|\$HOME|\$\{HOME\}|/home/yourt)?/*zchat-nu7-sdk/zcash-swift-wallet-sdk"
                        r"(?=/|$|[\s;&|)'\"<>])")   # the whole path, so no bare "/home/yourt/" is left behind
_END = r"(?=$|[\s;&|)'\"<>])"
MENTION = re.compile(r"zchat-android|zchat-worktrees|zchat-nu7-sdk|zchat-qa|zchat-denylist|zchat-?[*?\[]|"
                     r"zchat(?![\w-])|(~|/home/yourt|\$HOME|\$\{HOME\}|~yourt)/+\.config/*" + _END + "|"
                     r"(~|/home/yourt|\$HOME|\$\{HOME\}|~yourt)/*" + _END + r"|(^|[\s='\"])/home/?" + _END + "|"
                     r"(^|[\s='\"(])/+" + _END)
PARITY_MENTION = re.compile(r"(^|[\s=/'\"])parity/+(PARITY\.|areas|releases|exceptions|texts|SPEC_PIN|VECTORS|"
                            r"testdata|runner|verdicts|snapshots|\*)")

READONLY = {"cat", "less", "more", "head", "tail", "wc", "grep", "egrep", "fgrep", "rg", "ls", "stat", "file",
            "sha256sum", "sha1sum", "sha512sum", "md5sum", "b2sum", "cmp", "diff", "echo", "printf", "true", "false",
            "test", "[", "[[", "pwd", "date", "basename", "dirname", "realpath", "readlink", "sort", "uniq", "cut",
            "tr", "column", "jq", "xxd", "od", "strings", "tree", "du", "df", "nl", "fold", "comm", "join", "paste",
            "cd", "pushd", "popd", "exit", "sleep", "id", "whoami", "uname", "hostname", "env", "printenv", "which",
            "type", "command", "hexdump", "base64", "iconv", "expand", "unexpand", "rev", "tac", "fmt", "pr",
            "seq", "numfmt", "sum", "cksum", "zcat", "bzcat", "xzcat", "zgrep", "awk", "gawk", "mawk", "sed",
            "find", "git", "flock", "set", "shopt", "local", "declare", "typeset", "read", "return", "wait",
            "shift", "unset", "trap", ":", "break", "continue", "in"}
COPY_TOOLS = {"cp", "install", "rsync", "tar", "mkdir", "ln", "tee", "unzip"}      # destinations checked precisely
KEYWORDS = {"do", "then", "else", "elif", "while", "until", "if", "!", "{", "}", "time", "fi", "done", "esac",
            "function", "coproc"}
LIST_HEADS = {"for", "select", "case"}          # `for x in a b` names data, not a program
WRITE_ANY = {"rm", "rmdir", "touch", "mkdir", "truncate", "chmod", "chown", "chgrp", "shred", "unlink", "tee",
             "setfacl", "chattr"}
WRITE_DEST = {"cp", "install", "rsync"}
GIT_READ = {"log", "show", "diff", "status", "rev-parse", "ls-files", "ls-tree", "cat-file", "blame", "grep",
            "describe", "archive", "shortlog", "name-rev", "merge-base", "for-each-ref", "rev-list", "count-objects",
            "show-ref", "var", "version", "help", "whatchanged", "range-diff", "check-ignore", "check-attr",
            "verify-commit", "verify-tag", "cherry", "ls-remote"}
GIT_BRANCH_READ = {"--list", "-l", "-a", "--all", "-r", "--remotes", "--show-current", "-v", "-vv", "--contains",
                   "--merged", "--no-merged", "--points-at", "--format", "--sort", "--no-color", "--color"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "su"}
SEP_CHARS = set(";&|()\n")
REDIR_RX = re.compile(r"^(\d*|&)(>>?|>\||<>|>&|<|<<<|&>>?)$")
GH_CONTROL = re.compile(r"(environments|secrets|variables|/keys\b|deploy[-_]keys|branches/\S*/protection|rulesets|"
                        r"actions/permissions|deployments|pending_deployments|collaborators|/hooks\b|billing|"
                        r"budget|spending|visibility|/dispatches|/transfer|/invitations)", re.I)
GH_REPO_ROOT = re.compile(r"^/?repos/[^/\s]+/[^/\s]+/?$")
GH_API_HOST = re.compile(r"(^|[^\w.-])(api|uploads)\.github\.com", re.I)   # reached only through `gh api`


# ---------------------------------------------------------------- paths
def _norm(p, cwd):
    """An absolute normalized path, or "" for nothing, or "?" when the path cannot be known statically."""
    p = p.strip()
    if not p:
        return ""
    p = re.sub(r"^(\$HOME|\$\{HOME\}|~yourt)(?=/|$)", HOME, p)
    if p.startswith("~/") or p == "~":
        p = HOME + p[1:]
    if re.search(r"[$`*?\[\]{}]|^~", p):
        return "?"
    if not p.startswith("/") and cwd == "?":
        return "?"
    if not p.startswith("/"):
        p = os.path.join(cwd or HOME, p)
    p = os.path.normpath(p)
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):
        return p


def _under(p, root):
    return p == root or p.startswith(root + "/")


def foreign(p):
    """The protected root `p` is inside, or that `p` contains (a parent), or None. "?" counts as protected."""
    if not p:
        return None
    if p == "?":
        return "an unresolved path"
    if LOCK_OK.match(p) or any(_under(p, ok) for ok in FOREIGN_OK):
        return None
    for root in FOREIGN:
        if _under(p, root) or _under(root, p):
            return root
    return None


def parity_file(p):
    if p == "?":
        return False
    return bool(p) and (any(_under(p, r) for r in PARITY_ROOTS) or bool(PARITY_WT.match(p)))


def mentions(cmd):
    text = MENTION_OK.sub(" ", cmd)
    return bool(MENTION.search(text)), bool(PARITY_MENTION.search(text))


# ---------------------------------------------------------------- parsing
def _heredocs(cmd):
    """Split heredoc bodies out of the command. Returns (command_without_bodies, [(head_line, body)])."""
    lines = cmd.split("\n")
    out, bodies, i = [], [], 0
    while i < len(lines):
        ln = lines[i]
        out.append(ln)
        delims = re.findall(r"<<(-?)\s*(['\"]?)([A-Za-z_][\w-]*)\2", ln)
        i += 1
        for dash, _q, tag in delims:
            body = []
            while i < len(lines) and (lines[i].strip() if dash else lines[i]) != tag:
                body.append(lines[i])
                i += 1
            i += 1
            bodies.append((ln, "\n".join(body)))
    return "\n".join(out), bodies


def _tokens(cmd):
    cmd = cmd.replace("\\\n", " ")
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    toks = []
    for t in lex:
        toks.append(t)
    return toks


def _segments(cmd):
    """[(depth_change, tokens)] split on ; & | ( ) and newlines. None if the text cannot be tokenized."""
    try:
        toks = _tokens(cmd)
    except ValueError:
        return None
    segs, cur = [], []
    for t in toks:
        if t and set(t) <= SEP_CHARS | {"\n"} and not REDIR_RX.match(t):
            if cur:
                segs.append(("", cur))
            cur = []
            for ch in t:
                if ch in "()":
                    segs.append((ch, []))
        elif "\n" in t and t.strip() == "":
            if cur:
                segs.append(("", cur))
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(("", cur))
    return segs


def _split_redirs(seg):
    """(redirect targets written, input files read, args). `2>`, `>&`, `&>` and fd duplications are understood."""
    outs, ins, args, i = [], [], [], 0
    while i < len(seg):
        t = seg[i]
        if t.isdigit() and i + 1 < len(seg) and REDIR_RX.match(seg[i + 1]):
            i += 1
            continue
        m = REDIR_RX.match(t)
        if m:
            op = m.group(2)
            nxt = seg[i + 1] if i + 1 < len(seg) else ""
            if nxt == "&" and i + 2 < len(seg):            # >& file is split into '>' '&' 'file' by shlex
                nxt = seg[i + 2]
                i += 1
            if op in ("<", "<<<"):
                if op == "<":
                    ins.append(nxt)
            elif op == ">&" and (nxt.isdigit() or nxt == "-"):
                pass
            elif re.fullmatch(r"\d+|-", nxt) and seg[i + 1:i + 2] == ["&"]:
                pass
            else:
                outs.append(nxt)
            i += 2
            continue
        if t.startswith("<<"):
            i += 2
            continue
        args.append(t)
        i += 1
    return outs, ins, args


def _strip_prefix(args, env):
    """Drop VAR=… (recording GIT_DIR / GIT_WORK_TREE), keywords and wrappers (sudo, env, timeout, nice, …)."""
    changed = True
    while args and changed:
        changed = False
        while args and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", args[0]):
            k, v = args[0].split("=", 1)
            env[k] = v
            args = args[1:]
            changed = True
        while args and args[0] in KEYWORDS:
            args = args[1:]
            changed = True
        if args and args[0] in ("sudo", "env", "nohup", "time", "command", "exec", "nice", "timeout", "stdbuf",
                                "ionice", "xargs", "watch", "doas", "then"):
            w = args[0]
            args = args[1:]
            while args and (args[0].startswith("-") or re.match(r"^\d+(\.\d+)?[smhd]?$", args[0])):
                takes = args[0] in ("-n", "-c", "-d", "-I", "-L", "-P", "-s", "-k", "-u", "-g", "-E", "-i", "-o")
                args = args[2:] if (takes and w in ("xargs", "sudo", "stdbuf", "nice", "ionice")) else args[1:]
            changed = True
    return args


def _paths(args):
    return [a for a in args if not a.startswith("-")]


FLOCK_VALUED = {"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"}


def _unwrap_flock(args):
    while args and os.path.basename(args[0]) == "flock":
        i = 1
        while i < len(args) and args[i].startswith("-") and args[i] not in ("-c", "--command"):
            i += 2 if args[i] in FLOCK_VALUED else 1
        i += 1
        if i < len(args) and args[i] in ("-c", "--command"):
            return [], (args[i + 1] if i + 1 < len(args) else "")
        args = args[i:]
    return args, None


def _nested(args):
    prog = os.path.basename(args[0])
    if prog == "eval":
        return " ".join(args[1:])
    if prog in SHELLS:
        for i, a in enumerate(args[1:], 1):
            if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a) and i + 1 < len(args):
                return args[i + 1]
    return None


def _substitutions(cmd):
    """The inner commands of $(…) and `…` (one level; nested ones are found again by recursion)."""
    out = re.findall(r"`([^`]*)`", cmd)
    i = 0
    while True:
        j = cmd.find("$(", i)
        if j < 0:
            break
        depth, k = 1, j + 2
        while k < len(cmd) and depth:
            depth += {"(": 1, ")": -1}.get(cmd[k], 0)
            k += 1
        out.append(cmd[j + 2:k - 1])
        i = k
    return out


# ---------------------------------------------------------------- rules
# WI-9 (owner: full GitHub access) narrowed by review (WI-10): the iOS session may create its own PRIVATE repos and
# point its own trees at them. Allowed ONLY when the WHOLE Bash command is one of these exact shapes (fullmatch on the
# raw text, before any parsing): no expansion, no other flag or flag position, no env prefix but GH_TOKEN="$NAME",
# no cd/pushd/popd, no --git-dir/--work-tree/-c. Any other shape falls through to the normal rules, which refuse.
IOS_REPO_TREES = {  # repo -> its tree (fullmatch)
    "zchat-ios": re.compile(r"/home/yourt/(zchat-ios|zchat-ios-wt/[a-z0-9]+(-[a-z0-9]+)*)"),
    "zchat-spec": re.compile(r"/home/yourt/zchat-spec"),
    "zcash-swift-wallet-sdk-nu7": re.compile(r"/home/yourt/zchat-nu7-sdk/zcash-swift-wallet-sdk"),
    "zchat-ios-release": re.compile(r"/home/yourt/zchat-ios-release"),
}
_IOS_NAME = r"(zchat-ios|zchat-spec|zcash-swift-wallet-sdk-nu7|zchat-ios-[a-z0-9]+(?:-[a-z0-9]+)*)"
WI9_CREATE = re.compile(r'(?:GH_TOKEN="\$[A-Z][A-Z0-9_]*" )?gh repo create decentrathai/' + _IOS_NAME +
                        r' --private(?: (?:--description|-d) "[A-Za-z0-9 .,:/+_-]*")?')
WI9_DEFAULT_BRANCH = re.compile(r'(?:GH_TOKEN="\$[A-Z][A-Z0-9_]*" )?gh api -X PATCH repos/decentrathai/' + _IOS_NAME +
                                r' -f default_branch=[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9_-]*)*')
WI9_REMOTE = re.compile(r"git(?: -C (/home/yourt/[a-z0-9][a-z0-9/-]*))? remote add origin "
                        r"https://github\.com/decentrathai/([a-z0-9-]+?)(?:\.git)?")
WI9_BAD_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT",
               "GIT_CONFIG_PARAMETERS", "GH_HOST", "GH_REPO", "GH_CONFIG_DIR", "GH_ENTERPRISE_TOKEN")


def _read(p):
    try:
        with open(p) as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def _wi9_gitdir_ok(g):
    """A real (not linked) git dir that keeps its own config: no commondir, config a regular file without includes."""
    if os.path.islink(g) or not os.path.isdir(g) or os.path.realpath(g) != g:
        return False
    if os.path.lexists(os.path.join(g, "commondir")):
        return False
    cfg = os.path.join(g, "config")
    if os.path.islink(cfg) or not os.path.isfile(cfg):
        return False
    text = _read(cfg)
    return text is not None and not re.search(r"\[\s*include", text, re.I)


def _wi9_tree_ok(tree, ios_git=None, lane_root=None):
    """What git will really write: `git remote add` writes <common git dir>/config. The tree must exist at its
    canonical path, and its .git must be its own real git dir, or for a zchat-ios lane, a worktree file pointing at
    <zchat-ios>/.git/worktrees/<x> whose commondir is ../.. (WI-9 review v2)."""
    ios_git = ios_git or HOME + "/zchat-ios/.git"
    lane_root = lane_root or HOME + "/zchat-ios-wt"
    if not os.path.isdir(tree) or os.path.realpath(tree) != tree:
        return False
    g = os.path.join(tree, ".git")
    if os.path.islink(g):
        return False
    if os.path.isdir(g):
        return _wi9_gitdir_ok(g)
    if not os.path.isfile(g) or os.path.dirname(tree) != lane_root:
        return False
    m = re.fullmatch(r"gitdir: (.+)", (_read(g) or "").strip())
    if not m or os.path.dirname(m.group(1)) != os.path.join(ios_git, "worktrees"):
        return False
    wd = m.group(1)
    if os.path.islink(wd) or not os.path.isdir(wd) or os.path.realpath(wd) != wd:
        return False
    if os.path.islink(os.path.join(wd, "commondir")) or (_read(os.path.join(wd, "commondir")) or "").strip() != "../..":
        return False
    return _wi9_gitdir_ok(ios_git)


# Files that steer git, gh or every new shell (GIT_DIR, aliases, url rewrites); the agent never writes them.
STEER_FILES = [HOME + "/.bashrc", HOME + "/.profile", HOME + "/.bash_profile", HOME + "/.bash_login",
               HOME + "/.bash_logout", HOME + "/.zshrc", HOME + "/.zshenv", HOME + "/.gitconfig", HOME + "/.config/git",
               HOME + "/.config/gh", HOME + "/.inputrc", HOME + "/.bash_aliases", HOME + "/.zprofile",
               HOME + "/bin", HOME + "/.local/bin"]


def steer_file(p):
    return bool(p) and p != "?" and any(_under(p, f) for f in STEER_FILES)


# Free-tier CI rule (owner 23 Nov 2026: no GitHub charge, the account is GitHub Free; IOSP-16: upstream's .github in
# the SDK fork ran 16 Dependabot PRs on macOS at 10x). A push is refused while the pushed tree holds a workflow that
# can spend more than a short Linux run. Read line by line, no YAML library: what this reader cannot follow is refused.
CI_RUNNER_OK = re.compile(r"ubuntu-(?:latest|\d{2}\.\d{2})")
CI_MAX_TIMEOUT = 30


def _ci_value(v):
    v = re.sub(r"\s+#.*$", "", v).strip()
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v


def workflow_cost_problem(name, text):
    """None when every job of this workflow text is a short GitHub-hosted ubuntu run; else why not."""
    rows = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        if "\t" in raw[:len(raw) - len(raw.lstrip())]:
            return "%s: tab indentation" % name
        s = raw.strip()
        if s and not s.startswith("#"):
            rows.append((len(raw) - len(raw.lstrip(" ")), s))
    for _, s in rows:
        k = re.match(r"^(?:-\s+)?([\w-]+)\s*:", s)
        if k and k.group(1) in ("schedule", "workflow_run"):
            return "%s: a %s trigger starts runs with no push" % (name, k.group(1))
        if k and k.group(1) == "matrix":
            return "%s: a matrix multiplies the minutes" % name
    top = [i for i, (ind, s) in enumerate(rows) if ind == 0 and re.match(r"^[\"']?jobs[\"']?\s*:", s)]
    if len(top) != 1 or not re.fullmatch(r"jobs\s*:", rows[top[0]][1]):
        return "%s: no plain block-style `jobs:` line" % name
    body = []
    for ind, s in rows[top[0] + 1:]:
        if ind == 0:
            break
        body.append((ind, s))
    if not body:
        return "%s: no jobs" % name
    jind = body[0][0]
    jobs, cur = [], None
    for ind, s in body:
        if ind < jind:
            return "%s: jobs indentation not followed" % name
        if ind == jind:
            if not re.fullmatch(r"[\w-]+\s*:", s):
                return "%s: job line `%s` not followed" % (name, s[:40])
            cur = [s.split(":")[0].strip(), []]
            jobs.append(cur)
        else:
            cur[1].append((ind, s))
    for job, lines in jobs:
        if not lines:
            return "%s: job %s is empty" % (name, job)
        cind = lines[0][0]
        keys = {}
        for ind, s in lines:
            m = re.match(r"^([\w-]+)\s*:(.*)$", s) if ind == cind else None
            if m:
                keys[m.group(1)] = _ci_value(m.group(2))
        if "uses" in keys:
            return "%s: job %s calls another workflow" % (name, job)
        if not CI_RUNNER_OK.fullmatch(keys.get("runs-on", "")):
            return "%s: job %s runs-on %r, only a GitHub-hosted ubuntu runner on one line" % (
                name, job, keys.get("runs-on"))
        t = keys.get("timeout-minutes", "")
        if not re.fullmatch(r"\d{1,2}", t) or not 1 <= int(t) <= CI_MAX_TIMEOUT:
            return "%s: job %s needs its own timeout-minutes of 1..%d (has %r)" % (name, job, CI_MAX_TIMEOUT, t or None)
    return None


def _git_top(p):
    q = p
    while q and q != "/":
        if os.path.lexists(os.path.join(q, ".git")):
            return q
        q = os.path.dirname(q)
    return p


def tree_cost_problem(root):
    """None when the tree at root holds no workflow or dependabot file that can cost money; else why not."""
    gh = os.path.join(root, ".github")
    for n in ("dependabot.yml", "dependabot.yaml"):
        if os.path.lexists(os.path.join(gh, n)):
            return ".github/%s opens PRs that start runs (IOSP-16)" % n
    wd = os.path.join(gh, "workflows")
    if not os.path.lexists(wd):
        return None
    if os.path.islink(wd) or not os.path.isdir(wd):
        return ".github/workflows is not a plain folder"
    try:
        names = sorted(os.listdir(wd))
    except OSError:
        return ".github/workflows cannot be read"
    for n in names:
        if not n.endswith((".yml", ".yaml")):
            continue
        try:
            with open(os.path.join(wd, n), encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            return ".github/workflows/%s cannot be read" % n
        why = workflow_cost_problem(n, text)
        if why:
            return why
    return None


def wi9_exact(cmd, cwd):
    """True only for the two WI-9 commands in their exact shape (see the comment above IOS_REPO_TREES). cwd must be
    the hook payload's own cwd ("" when the payload had none)."""
    if any(os.environ.get(k) for k in WI9_BAD_ENV):
        return False
    if WI9_CREATE.fullmatch(cmd) or WI9_DEFAULT_BRANCH.fullmatch(cmd):
        return True
    m = WI9_REMOTE.fullmatch(cmd)
    if not m or m.group(2) not in IOS_REPO_TREES:
        return False
    tree = m.group(1) or cwd or ""
    return bool(tree) and bool(IOS_REPO_TREES[m.group(2)].fullmatch(tree)) and _wi9_tree_ok(tree)


def check_git(args, cwd, env):
    a = args[1:]
    bad = sorted(k for k in env if k.startswith("GIT_CONFIG") and k != "GIT_CONFIG_NOSYSTEM")
    if bad:
        return "%s sets git config the guard never sees (A14, WI-9 review)" % bad[0]
    repo = env.get("GIT_DIR") or env.get("GIT_WORK_TREE")
    repo = _norm(re.sub(r"/\.git/?$", "", repo), cwd) if repo else cwd
    i, sub, rest = 0, None, []
    while i < len(a):
        x = a[i]
        if x == "-C" and i + 1 < len(a):
            repo = _norm(a[i + 1], repo)
            i += 2
        elif x == "-c" and i + 1 < len(a):
            if a[i + 1].lower().startswith("core.hookspath"):
                return "another core.hooksPath skips the hooks (A14)"
            if a[i + 1].lower().startswith("alias."):
                return "git -c alias.* can rename a refused command (A14, WI-9 review)"
            if a[i + 1].lower().startswith(("include.", "includeif.")):
                return "git -c include.* pulls in config the guard never sees (A14, WI-9 review)"
            if a[i + 1].lower().startswith(("remote.", "url.")):
                return "git -c remote.* / url.* redirects a fetch or push for one command (A14, WI-9 review)"
            i += 2
        elif x in ("--git-dir", "--work-tree") and i + 1 < len(a):
            repo = _norm(re.sub(r"/\.git/?$", "", a[i + 1]), repo)
            i += 2
        elif x.startswith("--git-dir=") or x.startswith("--work-tree="):
            repo = _norm(re.sub(r"/\.git/?$", "", x.split("=", 1)[1]), repo)
            i += 1
        elif x.startswith("-"):
            i += 1
        else:
            sub, rest = x, a[i + 1:]
            break
    if sub is None:
        return None
    low = [r.lower() for r in rest]
    if "--no-verify" in low or sub == "commit" and any(re.match(r"^-[a-zA-Z]*n[a-zA-Z]*$", r) for r in rest):
        return "git --no-verify / -n skips the hooks (A14)"
    if sub == "config":
        if any("hookspath" in r for r in low) and (len(_paths(rest)) > 1 or any(r.startswith("--unset") or
                                                   r.startswith("--replace") or r == "--add" for r in low)):
            return "changing core.hooksPath is refused (A14)"
        if any(re.match(r"^(remote\.[^.]+\.(push)?url|url\..*\.(push)?insteadof)$", r) for r in low) and \
                len(_paths(rest)) > 1:
            return "remote URLs are set by the owner only (plan C.1)"
        if any(r.startswith("alias.") for r in low) and (len(_paths(rest)) > 1 or any(
                r.startswith("--unset") or r.startswith("--replace") or r == "--add" for r in low)):
            return "setting a git alias can rename a refused command (A14, WI-9 review)"
        if any(r.startswith(("include.", "includeif.")) for r in low) and (len(_paths(rest)) > 1 or any(
                r.startswith("--unset") or r.startswith("--replace") or r == "--add" for r in low)):
            return "a git config include pulls in config the guard never sees (A14, WI-9 review)"
    if sub == "remote" and rest[:1] and rest[0] not in ("-v", "show", "get-url"):
        return "remotes are added and changed by the owner only; the one exception is the exact plain command " \
               "`git [-C <tree>] remote add origin https://github.com/decentrathai/<its repo>.git` (plan C.1, WI-9)"
    if sub == "push":
        for r in rest:
            v = r.split("=", 1)[1] if r.startswith("--repo=") else r
            if not r.startswith("-") or r.startswith("--repo="):
                if re.search(r"(://|^git@|^[\w-]+(\.[\w-]+)+:|^/|^\.\.?/)", v) or r.startswith("--repo="):
                    return "push to a URL instead of a named remote is refused (A14: no push to a public remote)"
        why = tree_cost_problem(_git_top(repo))
        if why:
            return "push refused by the free-tier CI rule (owner 23 Nov 2026, IOSP-16): " + why
    for r in rest + [a_ for a_ in a]:
        if SIGNING.search(r):
            return "signing material is never read, staged or shown through git (A14)"
    read = sub in GIT_READ or \
        sub == "branch" and all(r in GIT_BRANCH_READ or not r.startswith("-") and rest.index(r) > 0 and
                                rest[rest.index(r) - 1] in ("--contains", "--merged", "--no-merged", "--points-at",
                                                            "--format", "--sort") for r in rest) or \
        sub == "tag" and (not rest or rest[0] in ("-l", "--list", "-n", "--contains", "--points-at")) or \
        sub == "config" and len(_paths(rest)) <= 1 and not any(r.startswith("--unset") or r == "--add" for r in low) \
        or sub == "worktree" and rest[:1] == ["list"] or sub == "stash" and rest[:1] in (["list"], ["show"]) \
        or sub == "remote" and (not rest or rest[0] in ("-v", "show", "get-url")) \
        or sub == "symbolic-ref" and len(_paths(rest)) <= 1 and "-d" not in rest and "--delete" not in rest \
        or sub == "reflog" and rest[:1] in ([], ["show"]) or sub == "notes" and rest[:1] in ([], ["list"], ["show"])
    if sub == "archive":
        for j, r in enumerate(rest):
            if r in ("-o", "--output") and j + 1 < len(rest) or r.startswith("--output="):
                dest = rest[j + 1] if not r.startswith("--output=") else r.split("=", 1)[1]
                if foreign(_norm(dest, cwd)):
                    return "git archive --output into another code base is refused (A14)"
    if not read:
        root = foreign(repo)
        if root:
            return "git %s in %s writes into another code base (A14); hand a patch over the mailbox" % (sub, root)
        if sub in ("clone", "worktree", "init", "submodule"):
            for p in _paths(rest):
                if p.startswith("http") or "://" in p or p.startswith("git@"):
                    continue
                if foreign(_norm(p, repo)) and _norm(p, repo) != "?":
                    return "git %s into another code base is refused (A14)" % sub
    return None


def check_gh(args):
    a = args[1:]
    words = [x for x in a if not x.startswith("-")]
    sub = words[:2]
    joined = " ".join(a)
    if sub[:1] == ["release"] and sub[1:2] and sub[1] not in ("list", "view", "download"):
        return "gh release is publishing; only release_pipeline.py after a valid pass (A14)"
    if sub[:1] == ["workflow"] and sub[1:2] in (["run"], ["enable"], ["disable"]):
        return "starting or changing a workflow is refused until ci_verify.py exists; paid CI is a spend (WI-1 B8)"
    if sub[:1] == ["run"] and sub[1:2] in (["rerun"], ["cancel"], ["delete"]):
        return "gh run %s changes CI; refused until ci_verify.py exists (WI-1 B8)" % sub[1]
    if sub[:1] in (["secret"], ["variable"]) and "list" not in sub[1:2]:
        return "gh %s changes a GitHub control (A14)" % sub[0]
    for j, w in enumerate(words[:3]):  # an option value can shift the verb ("gh --repo x repo create"): look further
        if w == "repo" and words[j + 1:j + 2] and words[j + 1] not in ("view", "list", "clone") or \
                w == "alias" and words[j + 1:j + 2] and words[j + 1] != "list":
            sub = [w, words[j + 1]]
            break
    if sub[:1] == ["repo"] and sub[1:2] and sub[1] not in ("view", "list", "clone"):
        return "gh repo %s is refused: repos are changed or deleted by the owner; the one exception is the exact " \
               "plain `gh repo create decentrathai/<iOS repo> --private [-d \"text\"]` (plan C.1, WI-9)" % sub[1]
    if sub[:1] == ["alias"] and sub[1:2] and sub[1] not in ("list",):
        return "gh alias %s can rename a refused command (A14, WI-9 review)" % sub[1]
    if sub[:1] in (["ruleset"], ["environment"], ["org"], ["codespace"], ["extension"]) or \
            sub[:1] == ["auth"] and sub[1:2] and sub[1] not in ("status",):
        return "gh %s is refused (A14)" % sub[0]
    if sub[:1] == ["api"]:
        rest = a[a.index("api") + 1:]
        method, explicit, words_ = "GET", False, []
        i = 0
        while i < len(rest):
            x = rest[i]
            m = re.match(r"^(?:-X|--method=?)(\w*)$", x)
            if m:
                if m.group(1):
                    method = m.group(1).upper()
                else:
                    method = (rest[i + 1] if i + 1 < len(rest) else "").upper()
                    i += 1
                explicit = True
            elif re.match(r"^(-f|-F|--field|--raw-field|--input)$", x):
                if not explicit:
                    method = "POST"
                i += 1
            elif re.match(r"^(-f|-F|--field|--raw-field|--input)=|^-[fF]\S", x):
                if not explicit:
                    method = "POST"
            elif re.match(r"^(-H|--header|-q|--jq|-t|--template|--hostname|-p|--preview|--cache)$", x):
                i += 1
            elif not x.startswith("-"):
                words_.append(x)
            i += 1
        path = " ".join(words_)
        if "graphql" in path.split():
            if re.search(r"\bmutation\b", joined):
                return "a GitHub GraphQL mutation can change a control, a repo or billing (A14)"
            return None
        if method != "GET":
            first = path.split()[0] if path else ""
            if re.match(r"^/?(user|orgs/[^/]+)/repos/?$", first) or \
                    re.match(r"^/?repos/[^/]+/[^/]+/(forks|generate|transfer)/?$", first):
                return "gh api %s on %s creates, forks or moves a repo: repos are made by the owner (plan C.1)" % (
                    method, first[:80])
            if GH_CONTROL.search(path) or GH_REPO_ROOT.match(first):
                return "gh api %s on %s changes a GitHub control, a repo setting or billing (A14)" % (method, path[:80])
            if re.search(r"(/releases|/dispatches|/rerun|/actions/runs)", path):
                return "gh api %s on %s publishes or starts paid CI (A14)" % (method, path[:80])
    return None


def check_bash(cmd, cwd, depth=0, env=None, cwd_known=True):
    if depth > 6:
        return "commands nested more than six levels deep are refused (fail-closed)"
    if depth == 0 and wi9_exact(cmd, cwd if cwd_known else ""):
        return None
    env = dict(env or {})
    body_cmd, bodies = _heredocs(cmd)
    ment, pment = mentions(body_cmd)
    for head, body in bodies:
        h = _segments(head)
        progs = [os.path.basename(_strip_prefix(_split_redirs(s)[2], {})[0]) for _d, s in (h or [])
                 if _strip_prefix(_split_redirs(s)[2], {})]
        if any(p in SHELLS or p == "eval" for p in progs):
            why = check_bash(body, cwd, depth + 1, env)
            if why:
                return why
        elif any(p in ("python", "python3", "node", "perl", "ruby") for p in progs) and (ment or mentions(body)[0]):
            return "a program fed on stdin names another code base; it could write there (A14). Read in one step, " \
                   "write evidence in another"
    for inner in _substitutions(body_cmd):
        why = check_bash(inner, cwd, depth + 1, env)
        if why:
            return why
    segs = _segments(body_cmd)
    if segs is None:
        return "the guard cannot parse this command (unbalanced quotes); fail-closed"
    here = cwd or HOME
    stack = []
    for paren, seg in segs:
        if paren == "(":
            stack.append(here)
            continue
        if paren == ")":
            here = stack.pop() if stack else here
            continue
        outs, ins, args = _split_redirs(seg)
        if args[:1] == ["export"]:
            for x in args[1:]:
                if "=" in x:
                    k, v = x.split("=", 1)
                    env[k] = v
            continue
        args = _strip_prefix(args, env)
        if args[:1] and args[0] in LIST_HEADS:
            continue
        args, inner = _unwrap_flock(args)
        if inner is not None:
            why = check_bash(inner, here, depth + 1, env)
            if why:
                return why
            continue
        if args:
            inner = _nested(args)
            if inner is not None:
                why = check_bash(inner, here, depth + 1, env)
                if why:
                    return why
                continue
        for r in outs:
            p = _norm(r, here)
            if p.startswith("/dev/") or r in ("/dev/null", "&1", "&2"):
                continue
            root = foreign(p)
            if root and (p != "?" or ment):
                return "writing %s writes into another code base (%s); hand a patch over the mailbox" % (r, root)
            if parity_file(p) or p == "?" and pment:
                return "parity files are written only by tools/parity.py (plan D.2)"
            if steer_file(p):
                return "%s steers git, gh or every new shell; the owner changes it (A14, WI-9 review)" % r
            if SIGNING.search(p):
                return "writing signing material is refused (A14)"
        for r in ins:
            if SIGNING.search(_norm(r, here)) or SIGNING.search(r):
                return "signing material (%s) is never read (A14)" % os.path.basename(r)
        if not args:
            continue
        prog = os.path.basename(args[0])
        if prog in ("cd", "pushd"):
            dest = [x for x in args[1:] if not x.startswith("-") and not x.startswith("+")]
            new = _norm(dest[0], here) if dest else HOME
            here = new if new != "?" else ("?" if ment or pment else (cwd or HOME))
            continue
        if prog == "popd":
            continue
        if prog not in ("ls",):
            for x in args[1:]:
                x = x.strip("'\"")
                if SIGNING.search(x) or (not x.startswith("-") and SIGNING.search(_norm(x, here) or "")):
                    return "signing material (%s) is never read, copied or printed (A14)" % os.path.basename(x)
        if re.search(r"(^|/)fastlane(/|$)", here) and prog in ("cat", "less", "more", "head", "tail", "grep", "rg",
                                                                "base64", "xxd", "strings", "cp"):
            if any(re.search(r"(^|/)\.env", x) for x in args[1:]):
                return "fastlane/.env files are never read (A14)"
        if prog == "fastlane" or prog == "bundle" and "fastlane" in args[1:3]:
            if not any(x in ("lanes", "--help", "-h", "env", "list", "--version") for x in args[1:4]):
                return "running a fastlane lane may upload; only release_pipeline.py after a valid pass (A14)"
        if prog in ("altool", "iTMSTransporter", "Transporter", "notarytool") or prog == "xcrun" and any(
                x in ("altool", "notarytool", "iTMSTransporter") for x in args[1:2]):
            if not any(x in ("--help", "-h", "--version", "history", "info", "log", "list") for x in args[1:4]):
                return "an upload or submit to Apple is publishing (A14)"
        if prog == "xcodebuild" and "-exportArchive" in args:
            return "xcodebuild -exportArchive may upload; only the pipeline exports (A14)"
        if any("api.appstoreconnect.apple.com" in x for x in args):
            return "App Store Connect API calls go only through the pipeline (A14)"
        if prog == "security" and (args[1:2] in (["export"], ["export-identity"]) or
                                   "-w" in args and args[1:2] and "password" in args[1]):
            return "printing or exporting keychain items is refused (A14)"
        if prog in ("ssh", "scp", "sftp", "mosh") or prog == "rsync" and any(
                re.match(r"^[^/]*[\w.-]+:", x) for x in args[1:]):
            return "no ssh to servers; server work belongs to the backend session (A14)"
        if _under(here, THIRDPARTY) and (prog not in READONLY or prog == "git" and False) and prog != "git":
            return "no build, test or script run inside thirdparty (plan C.5)"
        if prog == "git":
            why = check_git(args, here, env)
            if why:
                return why
            continue
        if prog == "gh":
            why = check_gh(args)
            if why:
                return why
            continue
        if prog not in READONLY and any(GH_API_HOST.search(x) for x in args[1:]):
            return "GitHub's API is reached only through `gh api`, which the guard checks (%s; WI-9 review)" % prog
        if prog == os.path.basename(HEAVY) and _norm(args[0], here) == HEAVY:
            continue
        # The MENTION rule: a command naming a protected place runs only programs that cannot write there.
        if ment and prog not in READONLY and prog not in COPY_TOOLS:
            return ("this command names another code base and runs %s, which may write there (A14). Read in one "
                    "command, write evidence in another; a patch goes over the mailbox" % prog)
        if pment and prog not in READONLY:
            return "this command names a parity file and runs %s; parity files change only through parity.py" % prog
        if prog in ("awk", "gawk", "mawk") and any(re.search(r">|system|print\s*\|", x) for x in args[1:]) and \
                (ment or pment):
            return "awk that writes or runs commands, on a command naming a protected place (A14)"
        if prog == "find" and any(x in ("-delete", "-fprint", "-fprintf", "-fls") for x in args):
            if ment or pment or any(foreign(_norm(x, here)) for x in _find_roots(args)):
                return "find that deletes or writes, on a protected place (A14)"
        if prog == "find" and any(x in ("-exec", "-execdir", "-ok", "-okdir") for x in args):
            j = max(i for i, x in enumerate(args) if x in ("-exec", "-execdir", "-ok", "-okdir"))
            run = os.path.basename(args[j + 1]) if j + 1 < len(args) else ""
            if run not in READONLY - {"find", "git", "sed", "awk", "gawk", "mawk"} and (
                    ment or pment or any(foreign(_norm(x, here)) for x in _find_roots(args))):
                return "find -exec %s on a protected place (A14)" % run
        targets = []
        tdir = [args[i + 1] for i, x in enumerate(args[:-1]) if x in ("-t", "--target-directory")] + \
               [x.split("=", 1)[1] for x in args if x.startswith("--target-directory=")]
        if prog in WRITE_ANY:
            targets = _paths(args[1:])
        elif prog == "ln":
            targets = _paths(args[1:])[-1:]
        elif prog == "mv":
            targets = _paths(args[1:]) + tdir
        elif prog in WRITE_DEST:
            ps = [x for x in _option_free(args[1:])]
            targets = (ps[-1:] if not tdir else []) + tdir
        elif prog in ("sed", "perl") and any(re.match(r"^-[a-zA-Z]*i", x) or x.startswith("--in-place")
                                             for x in args[1:]):
            targets = _paths(args[1:]) if prog == "perl" else _paths(args[1:])[1:] + ["?"]
        elif prog == "sed" and any(re.search(r"(^|[;/\s])w\s+\S", x) for x in args[1:]):
            targets = [m.group(1) for x in args[1:] for m in [re.search(r"w\s+(\S+)", x)] if m]
        elif prog == "dd":
            targets = [x[3:] for x in args[1:] if x.startswith("of=")]
        elif prog == "tar":
            if any(re.match(r"^-?[a-zA-Z]*x", x) for x in args[1:2]) or "--extract" in args or "-x" in args:
                targets = [here]
                for i, x in enumerate(args):
                    if x in ("-C", "--directory") and i + 1 < len(args):
                        targets = [args[i + 1]]
                    elif x.startswith("--directory="):
                        targets = [x.split("=", 1)[1]]
                    elif re.match(r"^-[a-zA-Z]*C$", x) and i + 1 < len(args):
                        targets = [args[i + 1]]
        elif prog == "unzip":
            targets = args[args.index("-d") + 1:args.index("-d") + 2] if "-d" in args else [here]
        elif prog == "patch":
            targets = [here]
            for i, x in enumerate(args):
                if x == "-d" and i + 1 < len(args):
                    targets = [args[i + 1]]
                elif x.startswith("--directory="):
                    targets = [x.split("=", 1)[1]]
            targets += [x for x in _paths(args[1:]) if not x.isdigit()]
        elif prog in ("curl", "wget"):
            for i, x in enumerate(args):
                if x in ("-o", "--output", "-O", "-P", "--directory-prefix", "--output-document") and \
                        i + 1 < len(args) and not (prog == "curl" and x == "-O"):
                    targets.append(args[i + 1])
                elif re.match(r"^--(output|output-document|directory-prefix)=", x):
                    targets.append(x.split("=", 1)[1])
            if prog == "curl" and "-O" in args or prog == "wget" and not targets:
                targets.append(here)
        for t in targets:
            p = _norm(t, here)
            root = foreign(p)
            if root and (p != "?" or ment):
                return "%s on %s writes into another code base (%s); hand a patch over the mailbox" % (prog, t, root)
            if parity_file(p) or p == "?" and pment:
                return "parity files are written only by tools/parity.py (plan D.2)"
            if steer_file(p):
                return "%s on %s: that file steers git, gh or every new shell (A14, WI-9 review)" % (prog, t)
    return None


def _find_roots(args):
    roots = []
    for x in args[1:]:
        if x.startswith("-") or x in ("(", "!", ")"):
            break
        roots.append(x)
    return roots or ["."]


def _option_free(args):
    """Path arguments of cp/rsync/install without option values (`--exclude X`, `-e ssh`)."""
    out, skip = [], False
    for x in args:
        if skip:
            skip = False
            continue
        if x.startswith("-"):
            skip = x in ("--exclude", "--include", "-e", "--rsh", "--filter", "-f", "--suffix", "-S", "-m", "--mode",
                         "-o", "--owner", "-g", "--group", "--chmod", "--exclude-from", "--include-from",
                         "--files-from", "-t", "--target-directory")
            continue
        out.append(x)
    return out


def check_file_tool(tool, ti, cwd):
    path = ti.get("file_path") or ti.get("notebook_path") or ti.get("path") or ""
    p = _norm(path, cwd) if path else ""
    if tool in ("Read", "Grep", "Glob"):
        if p and (SIGNING.search(p) or SIGNING_DIR.search(p)):
            return "signing material is never read (A14)"
        pat = ti.get("glob", "") if tool == "Grep" else ti.get("pattern", "") if tool == "Glob" else ""
        if pat and SIGNING.search(str(pat).replace("*", "x")):
            return "signing material is never searched (A14)"
        return None
    root = foreign(p)
    if root:
        return "writing %s writes into another code base (%s); hand a patch over the mailbox (A14)" % (path, root)
    if steer_file(p):
        return "%s steers git, gh or every new shell; the owner changes it (A14, WI-9 review)" % path
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
        return check_bash(str(ti.get("command", "")), cwd, cwd_known=bool(payload.get("cwd")))
    if tool in ("Read", "Grep", "Glob", "Write", "Edit", "MultiEdit", "NotebookEdit"):
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
