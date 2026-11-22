"""commit-msg for the iOS repo (plan E, annex A14; IOSP-3). Every refusal starts with BLOCKED and says the way forward.

Stricter than Android's on purpose (Fable harness review, 22 Nov 2026): there is no [no-red:] escape, and feat( is
held to the RED rule like fix(.
"""
import os
import re
import subprocess
import sys

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

    product = [p for p in paths if kinds[p] in ("product", "other")]
    if product:
        block("%s %s product code or not classified. A product commit is judged by parity.py check-commit from "
              "zchat-spec trunk (plan D.5, tool step P0), which does not exist yet: nothing outside tests, harness "
              "and docs can be committed until it does." % (", ".join(product[:5]),
                                                           "is" if len(product) == 1 else "are"))
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
