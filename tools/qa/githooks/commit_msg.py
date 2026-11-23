"""commit-msg for the iOS repo (plan E, annex A14; IOSP-3). Every refusal starts with BLOCKED and says the way forward.

Stricter than Android's on purpose (Fable harness review, 22 Nov 2026): there is no [no-red:] escape, and feat( is
held to the RED rule like fix(.

A commit that stages a product, unclassified or parity/SPEC_PIN path is judged by parity.py check-commit, read from the
spec clone's committed trunk (plan D.5, tool step P0). The clone's path is a fixed literal: no environment variable can
point the hook at another spec. Only exit 0 with PARITY PASS lets the commit go; everything else fails closed.
"""
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import kind  # noqa: E402

TYPES = ("feat", "fix", "perf", "refactor", "test", "docs", "build", "chore", "style", "ci", "revert")
SUBJECT = re.compile(r"^(%s)(\([A-Za-z0-9._/-]+\))?!?: \S" % "|".join(TYPES))
NEEDS_RED = ("feat", "fix", "perf")
ASSERTION = re.compile(r"(XCTAssert\w*|XCTFail|XCTUnwrap|#expect|#require|\bassert\w*|@Test\b|\bfunc test\w*|"
                       r"\bdef test\w*|@Suite\b)")
SKIP = re.compile(r"(XCTSkip|\.disabled\(|withKnownIssue|@unittest\.skip|skipTest\(|\.enabled\(if:|"
                  r"@available\(\*,\s*unavailable|@pytest\.mark\.skip|expectedFailure)")
TAG = r"\[%s:\s*([^\]]*?)\s*\]"
MIN_REASON = 15
SPEC_DIR = "/home/yourt/zchat-spec"
SPEC_TOOL = "refs/heads/trunk:tools/parity.py"
JUDGED = ("product", "other", "pin")
REPO_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
             "GIT_COMMON_DIR", "GIT_PREFIX", "GIT_NAMESPACE", "GIT_QUARANTINE_PATH", "GIT_CEILING_DIRECTORIES",
             "GIT_DISCOVERY_ACROSS_FILESYSTEM")
TOOL_TIMEOUT = 300


def git(*args):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    return subprocess.run(["git", *args], capture_output=True, text=True, env=env)


def block(msg):
    print("BLOCKED: " + msg)
    sys.exit(1)


def staged():
    r = git("diff", "--cached", "--name-status", "-M")
    if r.returncode:
        block("git diff --cached failed: %s" % r.stderr.strip()[:200])
    paths, deleted = [], []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        status, names = parts[0], parts[1:]
        paths += names
        if status.startswith("D"):
            deleted += names
        if status.startswith("R"):
            deleted.append(names[0])
    return sorted(set(paths)), sorted(set(deleted))


def tag(body, name):
    """The longest filled-in value of [name: ...]; an empty mention in prose does not count."""
    values = [v for v in re.findall(TAG % re.escape(name), body) if v]
    return max(values, key=len) if values else None


def check_red(body, ctype):
    reds = re.findall(r"\[red:([0-9a-fA-F]{7,40})\]", body)
    if not reds:
        block("a %s( commit that changes code names its failing test commit with [red:<sha>]: commit the test "
              "first as test(...), then this one. This repo has no [no-red:] escape (AGENTS.md rule 1)." % ctype)
    for sha in reds:
        r = git("rev-parse", "-q", "--verify", sha + "^{commit}")
        if r.returncode:
            block("[red:%s] is not a commit in this repo" % sha)
        full = r.stdout.strip()
        if git("merge-base", "--is-ancestor", full, "HEAD").returncode:
            block("[red:%s] is not an ancestor of HEAD: the failing test must come first on this branch" % sha)
        files = [f for f in git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", full).stdout.split()]
        if not files:
            block("[red:%s] changes no file" % sha)
        bad = [f for f in files if kind(f) != "test"]
        if bad:
            block("[red:%s] must hold only test files; it also changes %s" % (sha, ", ".join(bad[:5])))
        subject = git("log", "-1", "--format=%s", full).stdout.strip()
        if not re.match(r"^test(\([^)]*\))?: ", subject):
            block("[red:%s] is not a test( commit (its subject: %s)" % (sha, subject[:80]))


def trunk_tool():
    """The bytes of tools/parity.py on the spec clone's trunk branch; never its working tree or HEAD."""
    if not os.path.isdir(SPEC_DIR):
        block("no spec clone at %s, so parity.py check-commit cannot judge this commit (fails closed)" % SPEC_DIR)
    env = {k: v for k, v in os.environ.items() if k not in REPO_VARS}
    env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_CEILING_DIRECTORIES=os.path.dirname(os.path.abspath(SPEC_DIR)))
    try:
        top = subprocess.run(["git", "-C", SPEC_DIR, "rev-parse", "--show-toplevel"], capture_output=True, env=env,
                             timeout=60)
        if top.returncode or os.path.realpath(top.stdout.decode(errors="replace").strip()) != os.path.realpath(
                SPEC_DIR):
            block("%s is not a git clone of the spec, so parity.py check-commit cannot judge this commit "
                  "(fails closed)" % SPEC_DIR)
        r = subprocess.run(["git", "-C", SPEC_DIR, "show", SPEC_TOOL], capture_output=True, env=env, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        block("cannot read tools/parity.py from %s trunk: %s" % (SPEC_DIR, e))
    if r.returncode or not r.stdout:
        block("%s has no committed tools/parity.py on trunk (%s), so parity.py check-commit cannot judge this "
              "commit (fails closed)" % (SPEC_DIR, r.stderr.decode(errors="replace").strip()[:200]))
    return r.stdout


def parity_check(msg_file):
    """Run trunk's parity.py check-commit on this commit; return only on exit 0 with PARITY PASS."""
    tool_bytes = trunk_tool()
    top = git("rev-parse", "--show-toplevel")
    if top.returncode:
        block("git rev-parse --show-toplevel failed: %s" % top.stderr.strip()[:200])
    with tempfile.TemporaryDirectory(prefix="ios-parity-") as d:
        tool = os.path.join(d, "parity.py")
        with open(tool, "wb") as fh:
            fh.write(tool_bytes)
        cmd = [sys.executable, "-I", tool, "--spec", SPEC_DIR, "check-commit", "--platform", "ios",
               "--repo", top.stdout.strip(), "--msg-file", os.path.abspath(msg_file)]
        try:
            t = subprocess.run(cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT,
                               env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1"))
        except (OSError, subprocess.SubprocessError) as e:
            block("parity.py check-commit did not run to the end: %s" % e)
    if t.returncode == 0 and "PARITY PASS" in t.stdout:
        return
    out = (t.stdout + t.stderr).strip() or "(no output)"
    block("parity.py check-commit refused this commit (exit %d, no PARITY PASS):\n%s" % (t.returncode, out))


def weakened_tests(test_paths, deleted):
    found = ["deleted %s" % p for p in deleted if kind(p) == "test"]
    if not test_paths:
        return found
    r = git("diff", "--cached", "-U0", "--no-color", "-M", "--", *test_paths)
    current = None
    for line in r.stdout.splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else current
        elif line.startswith("--- "):
            continue
        elif line.startswith("-") and ASSERTION.search(line):
            found.append("an assertion or test removed in %s" % current)
        elif line.startswith("+") and SKIP.search(line):
            found.append("a skip or known-issue marker added in %s" % current)
    return found


def main(argv):
    with open(argv[1], encoding="utf-8", errors="replace") as fh:
        body = "\n".join(l for l in fh.read().splitlines() if not l.startswith("#")).strip()
    if not body:
        block("empty commit message")
    subject = body.splitlines()[0]
    m = SUBJECT.match(subject)
    if not m:
        block("the subject must read type(scope): text, with type one of %s (got: %s)" % (", ".join(TYPES),
                                                                                          subject[:80]))
    ctype = m.group(1)
    paths, deleted = staged()
    if not paths:
        return 0
    kinds = {p: kind(p) for p in paths}

    if any(kinds[p] in JUDGED for p in paths):
        parity_check(argv[1])
    if ctype == "test":
        other = [p for p in paths if kinds[p] != "test"]
        if other:
            block("a test(...) commit is the RED commit and holds only test files; it also stages %s"
                  % ", ".join(other[:5]))
    harness = [p for p in paths if kinds[p] == "harness"]
    if harness and not tag(body, "harness-change"):
        block("%s %s harness files: add [harness-change: <why, and the W/WI or review it rests on>]"
              % (", ".join(harness[:5]), "is" if len(harness) == 1 else "are"))
    if ctype in NEEDS_RED and any(kinds[p] not in ("test", "doc") for p in paths):
        check_red(body, ctype)
    weak = weakened_tests([p for p in paths if kinds[p] == "test" and p not in deleted], deleted)
    if weak:
        reason = tag(body, "test-change-ok")
        if reason is None or len(reason) < MIN_REASON:
            block("this commit weakens tests (%s). If that is right, say why in [test-change-ok: <%d+ "
                  "characters>]; a committed test is never weakened to make code pass (AGENTS.md rule 1)."
                  % ("; ".join(weak[:5]), MIN_REASON))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
