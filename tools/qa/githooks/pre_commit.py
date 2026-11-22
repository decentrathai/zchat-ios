"""pre-commit for the iOS repo (plan E, annex A14; IOSP-3). Fails closed: a check that cannot run blocks.

1. No commit on main or master.
2. No Xcode project, signing, env or build-output file staged.
3. Vendored files equal tools/qa/vendor/VENDORED.lock (sha256), and nothing unlisted sits there.
4. The vendored Android secret scanner passes on the staged lines (it prints kinds and places, never values).
"""
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

FORBIDDEN = [
    (re.compile(r"\.xcodeproj(/|$)|\.pbxproj$"), "the Xcode project is generated from project.yml and never committed"),
    (re.compile(r"\.(p8|p12|pem|mobileprovision|provisionprofile|cer|keystore|jks)$|(^|/)AuthKey_"),
     "a signing or key file (the session never handles signing secrets, AGENTS.md rule 10)"),
    (re.compile(r"(^|/)\.env($|\.)"), "an env file"),
    (re.compile(r"(^|/)(DerivedData|\.build|xcuserdata)/"), "build output"),
]


def git(*args):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    return subprocess.run(["git", *args], capture_output=True, text=True, env=env)


def block(msg):
    print("BLOCKED: " + msg)
    sys.exit(1)


def main():
    top = git("rev-parse", "--show-toplevel")
    if top.returncode:
        block("not in a git work tree")
    root = Path(top.stdout.strip())
    branch = git("symbolic-ref", "--short", "-q", "HEAD").stdout.strip()
    if branch in ("main", "master"):
        block("commits on branch %s are refused: work on dev or a lane branch (AGENTS.md)" % branch)

    names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR").stdout.splitlines()
    for p in names:
        for rx, why in FORBIDDEN:
            if rx.search(p):
                block("%s is staged: %s" % (p, why))

    vendor = root / "tools/qa/vendor"
    lock = vendor / "VENDORED.lock"
    if not lock.is_file():
        block("tools/qa/vendor/VENDORED.lock is missing, so the vendored scanners cannot be trusted")
    listed = set()
    for line in lock.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            block("VENDORED.lock: a line is not '<sha256> <path> <source>'")
        digest, rel = parts[0], parts[1]
        listed.add(rel)
        f = vendor / rel
        if not f.is_file():
            block("VENDORED.lock: %s is missing from tools/qa/vendor" % rel)
        if hashlib.sha256(f.read_bytes()).hexdigest() != digest:
            block("VENDORED.lock: %s differs from the locked copy (re-vendor it from the named Android commit)" % rel)
    extra = sorted(p.relative_to(vendor).as_posix() for p in vendor.rglob("*")
                   if p.is_file() and p != lock and "__pycache__" not in p.parts)
    extra = [p for p in extra if p not in listed]
    if extra:
        block("VENDORED.lock: %s in tools/qa/vendor is not locked" % ", ".join(extra))
    scanner = vendor / "secret_scan.py"
    if "secret_scan.py" not in listed:
        block("secret_scan.py is not in VENDORED.lock")

    r = subprocess.run([sys.executable, "-I", str(scanner), "--hard-only", "staged", str(root)],
                       capture_output=True, text=True, cwd=str(root))
    if r.returncode == 1:
        block("the secret scan found a secret in the staged lines (kinds and places only):\n" +
              "\n".join(r.stdout.splitlines()[:20]))
    if r.returncode != 0:
        block("the secret scan could not run (exit %d), so nothing is committed: %s"
              % (r.returncode, (r.stderr or r.stdout).strip()[:300]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
