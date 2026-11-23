"""commit-msg judges product commits with parity.py check-commit from the spec's committed trunk (plan D.5; appendix X4
test 42; IOSP-3). Until now the hook blocked every product path because the tool did not exist; zchat-spec trunk
9e205c5 has it.

The seam (the contract the implementer builds to):

  commit_msg.py holds exactly one module-level line  SPEC_DIR = "/home/yourt/zchat-spec"  (a plain string literal,
  absolute). There is no environment override of any kind: the hook runs under `python3 -I`, which does not strip
  os.environ, so an env var read by the hook would let any session point a real commit at a spec it made up. The
  tests rewrite that one line in the temp repo's COPY of the hook (HookRepo copies tools/qa/githooks into every temp
  repo), never in the real file.

  When the staged paths include a product or unclassified path (paths.kind "product" or "other"), or parity/SPEC_PIN,
  the hook:
    1. reads the tool from the spec's committed trunk: `git -C SPEC_DIR show trunk:tools/parity.py` (with the
       commit's own GIT_DIR, GIT_INDEX_FILE, ... removed from that call's env) into a temp file outside the spec;
       never SPEC_DIR/tools/parity.py from the working tree, never the spec's HEAD;
    2. runs it: <python> <tempfile> --spec SPEC_DIR check-commit --platform ios --repo <repo top level>
       --msg-file <the commit message file>;
    3. lets the commit go only on exit 0 with "PARITY PASS" in stdout. Anything else blocks with "BLOCKED: ..." and the
       tool's own reason: tool exit 1, any other exit, a pass without "PARITY PASS", no spec clone at SPEC_DIR (the
       message names SPEC_DIR), no tools/parity.py on trunk (the message names parity.py). It fails closed.
  Commits that stage only test, harness and doc paths never call the tool (the tool's step 1 would refuse them before
  parity/ACTIVATION exists) and keep every rule they have today: test( holds only tests, [harness-change:], [red:],
  [test-change-ok:].

  The pin file is parity/SPEC_PIN (the tool's PIN_FILE, not a top-level SPEC_PIN). A commit that stages it is judged
  by the tool (which checks the pin is a commit the clone holds) and needs no [harness-change:]; the rest of parity/
  (the vendored files) stays product. Top-level SPEC_PIN (on trunk's iOS exempt list) is not product or other.

The end-to-end cases run the real tool (read from /home/yourt/zchat-spec trunk, never written) against a throwaway
spec built with its own ops; they need the laptop's spec clone and are skipped where it is absent (GitHub's runner).
The stub-tool cases run everywhere.
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_githooks as tg  # noqa: E402

QA = Path(__file__).resolve().parents[1]
HOOK = QA / "githooks" / "commit_msg.py"
REAL_SPEC = "/home/yourt/zchat-spec"
SEAM = re.compile(r"^SPEC_DIR = .*$", re.M)
OLD_TEXT = "does not exist yet"
HC = "\n\n[harness-change: test]"
PROTO = "Packages/ZChatCore/Sources/ZChatProtocol/X.swift"
PIN_FILE = "parity/SPEC_PIN"
STUB_NO = "stub-tool says no Parity trailer"

STUB = '''import json
import sys

REC = %(rec)r
MODE = %(mode)r
args = sys.argv[1:]
msg = None
if "--msg-file" in args and args.index("--msg-file") + 1 < len(args):
    try:
        with open(args[args.index("--msg-file") + 1], encoding="utf-8") as fh:
            msg = fh.read()
    except OSError:
        msg = None
with open(REC, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"argv0": sys.argv[0], "args": args, "msg": msg}) + "\\n")
if MODE == "pass":
    print("PARITY PASS: stub passes everything")
    sys.exit(0)
if MODE == "silent0":
    sys.exit(0)
if MODE == "crash":
    sys.stderr.write("stub-tool crashed\\n")
    sys.exit(2)
if msg and "Parity: PAR-" in msg:
    print("PARITY PASS: stub judged a trailer")
    sys.exit(0)
print("BLOCKED: %(no)s")
sys.exit(1)
'''


def _real_tool():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        r = subprocess.run(["git", "-C", REAL_SPEC, "show", "trunk:tools/parity.py"], capture_output=True, env=env,
                           timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 and b"check-commit" in r.stdout else None


REAL_TOOL = _real_tool()


def sh(repo, *args, env):
    r = subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, text=True)
    if r.returncode:
        raise AssertionError("git %s in %s: %s%s" % (args, repo, r.stdout, r.stderr))
    return r.stdout.strip()


def make_spec(where, tool_bytes, env):
    """A spec repo on trunk with tools/parity.py = tool_bytes (None: no tool) committed."""
    where = Path(where)
    where.mkdir(parents=True)
    sh(where, "init", "-q", "-b", "trunk", env=env)
    (where / "README.md").write_text("spec\n")
    if tool_bytes is not None:
        (where / "tools").mkdir()
        (where / "tools/parity.py").write_bytes(tool_bytes)
    sh(where, "add", "-A", env=env)
    sh(where, "commit", "-q", "-m", "chore: start", env=env)
    return where


class ParityHookCase(tg.HookRepo):
    def point_hook_at(self, spec):
        f = self.repo / "tools/qa/githooks/commit_msg.py"
        src = f.read_text(encoding="utf-8")
        self.assertEqual(len(SEAM.findall(src)), 1,
                         "commit_msg.py must hold exactly one module-level line `SPEC_DIR = \"<absolute path>\"`: "
                         "the seam these tests point at a throwaway spec clone")
        f.write_text(SEAM.sub(lambda m: "SPEC_DIR = %r" % str(spec), src), encoding="utf-8")
        self.pointed = spec

    def reset(self):
        """git reset --hard also restores the hook copy; point it again."""
        self.git("reset", "-q", "--hard")
        self.point_hook_at(self.pointed)

    def closed(self, msg, says=None):
        out = self.blocked(msg, says=says)
        self.assertNotIn(OLD_TEXT, out, "the hook still refuses product paths as if parity.py did not exist")
        return out

    def commit_env(self, msg, env):
        r = subprocess.run(["git", "-C", str(self.repo), "commit", "-q", "-m", msg], env=env, capture_output=True,
                           text=True)
        return r.returncode, r.stdout + r.stderr


class HookSource(unittest.TestCase):
    def test_spec_dir_is_one_absolute_literal(self):
        tree = ast.parse(HOOK.read_text(encoding="utf-8"))
        found = [n for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "SPEC_DIR" for t in n.targets)]
        self.assertEqual(len(found), 1, "commit_msg.py has no module-level SPEC_DIR = \"...\"")
        value = found[0].value
        self.assertIsInstance(value, ast.Constant, "SPEC_DIR must be a plain string literal, not computed")
        self.assertEqual(value.value, REAL_SPEC)

    def test_no_environment_override(self):
        src = HOOK.read_text(encoding="utf-8")
        for needle in ("getenv", "environ.get", "environ[", "expanduser"):
            with self.subTest(needle=needle):
                self.assertNotIn(needle, src)

    def test_spec_pin_classes(self):
        sys.path.insert(0, str(QA / "githooks"))
        try:
            import paths
        finally:
            sys.path.pop(0)
        self.assertNotIn(paths.kind("SPEC_PIN"), ("product", "other"))
        self.assertEqual(paths.kind("parity/testdata/money/q.json"), "product")
        self.assertEqual(paths.kind("parity/runner/swift/Runner.swift"), "product")


class StubTool(ParityHookCase):
    """The hook's wiring, with a stub parity.py committed on a throwaway spec's trunk. Runs everywhere."""

    def setUp(self):
        super().setUp()
        self.rec = Path(self.tmp) / "calls.jsonl"
        self.rec.write_text("")
        self.n = 0

    def spec(self, mode="judge"):
        self.n += 1
        return make_spec(Path(self.tmp) / ("spec%d" % self.n), self.stub(mode), self.env)

    def stub(self, mode):
        return (STUB % {"rec": str(self.rec), "mode": mode, "no": STUB_NO}).encode()

    def calls(self):
        return [json.loads(l) for l in self.rec.read_text().splitlines() if l.strip()]

    def test_product_commit_runs_trunk_tool_with_the_contract_args(self):
        spec = self.spec()
        self.point_hook_at(spec)
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.ok("refactor(app): a\n\nParity: PAR-0001")
        calls = self.calls()
        self.assertEqual(len(calls), 1, "the hook did not run the spec's parity.py once")
        a = calls[0]["args"]
        self.assertEqual(a[0], "--spec")
        self.assertEqual(os.path.realpath(a[1]), os.path.realpath(spec))
        self.assertEqual(a[2], "check-commit")
        rest = a[3:]
        self.assertEqual(len(rest) % 2, 0, a)
        opts = dict(zip(rest[::2], rest[1::2]))
        self.assertEqual(set(opts), {"--platform", "--repo", "--msg-file"}, a)
        self.assertEqual(opts["--platform"], "ios")
        self.assertEqual(os.path.realpath(opts["--repo"]), os.path.realpath(self.repo))
        self.assertIn("Parity: PAR-0001", calls[0]["msg"] or "")
        argv0 = os.path.realpath(calls[0]["argv0"])
        self.assertNotEqual(os.path.commonpath([argv0, os.path.realpath(spec)]), os.path.realpath(spec),
                            "the tool ran from the spec's working tree, not from a copy of trunk:tools/parity.py")

    def test_tool_refusal_blocks_with_its_reason(self):
        self.point_hook_at(self.spec())
        for path in ["Packages/ZChatCore/Sources/ZChatCore/A.swift", "App/Sources/A.swift", "project.yml",
                     "Packages/ZChatCore/Package.swift", "Unclassified/thing.txt"]:
            with self.subTest(path=path):
                self.put(path, "x\n")
                self.closed("refactor(core): a", says=STUB_NO)
                self.reset()
        self.assertEqual(len(self.calls()), 5)

    def test_tool_pass_lets_product_commit_through(self):
        self.point_hook_at(self.spec())
        for path in ["Packages/ZChatCore/Sources/ZChatCore/A.swift", "project.yml"]:
            with self.subTest(path=path):
                self.put(path, "x %s\n" % path)
                self.ok("refactor(core): a\n\nParity: PAR-0001")

    def test_other_rules_still_hold_on_product_commits(self):
        self.point_hook_at(self.spec())
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.blocked("feat(app): a\n\nParity: PAR-0001", says="[red:")
        self.reset()
        sha = self.red()
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.ok("feat(app): a [red:%s]\n\nParity: PAR-0001" % sha)
        self.put("App/Sources/B.swift", "struct B {}\n")
        self.put("tools/qa/tests/test_b.py", "def test_b():\n    assert False\n")
        self.blocked("test(app): b\n\nParity: PAR-0001", says="test(")

    def test_exit_zero_without_parity_pass_blocks(self):
        self.point_hook_at(self.spec("silent0"))
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.closed("refactor(app): a\n\nParity: PAR-0001")
        self.assertEqual(len(self.calls()), 1)

    def test_tool_crash_blocks(self):
        self.point_hook_at(self.spec("crash"))
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.closed("refactor(app): a\n\nParity: PAR-0001")
        self.assertEqual(len(self.calls()), 1)

    def test_weakened_working_tree_or_branch_tool_changes_nothing(self):
        spec = self.spec("judge")
        sh(spec, "checkout", "-q", "-b", "side", env=self.env)
        (spec / "tools/parity.py").write_bytes(self.stub("pass"))
        sh(spec, "commit", "-q", "-am", "weaken on a branch", env=self.env)
        (spec / "tools/parity.py").write_text("print('PARITY PASS: working tree')\n")
        self.point_hook_at(spec)
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.closed("refactor(app): a", says=STUB_NO)

    def test_environment_cannot_redirect_the_spec(self):
        judge, lenient = self.spec("judge"), self.spec("pass")
        self.point_hook_at(judge)
        env = dict(self.env)
        for k in ("ZCHAT_SPEC", "ZCHAT_SPEC_DIR", "ZCHAT_PARITY_SPEC", "SPEC_DIR", "PARITY_SPEC"):
            env[k] = str(lenient)
        self.put("App/Sources/A.swift", "struct A {}\n")
        rc, out = self.commit_env("refactor(app): a", env)
        self.assertNotEqual(rc, 0, "an env var pointed the hook at another spec")
        self.assertIn(STUB_NO, out)

    def test_missing_spec_clone_blocks_naming_it(self):
        gone = Path(self.tmp) / "no-such-spec"
        self.point_hook_at(gone)
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.closed("refactor(app): a\n\nParity: PAR-0001", says=str(gone))

    def test_spec_without_a_committed_tool_blocks(self):
        bare = make_spec(Path(self.tmp) / "toolless", None, self.env)
        (bare / "tools").mkdir()
        (bare / "tools/parity.py").write_bytes(self.stub("pass"))
        self.point_hook_at(bare)
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.closed("refactor(app): a\n\nParity: PAR-0001", says="parity.py")
        self.assertEqual(self.calls(), [], "the hook ran an uncommitted parity.py")

    def test_plain_directory_is_not_a_spec(self):
        plain = Path(self.tmp) / "plain"
        (plain / "tools").mkdir(parents=True)
        (plain / "tools/parity.py").write_bytes(self.stub("pass"))
        self.point_hook_at(plain)
        self.put("App/Sources/A.swift", "struct A {}\n")
        self.closed("refactor(app): a\n\nParity: PAR-0001")
        self.assertEqual(self.calls(), [])

    def test_pin_commit_is_judged_by_the_tool(self):
        self.point_hook_at(self.spec("pass"))
        self.put(PIN_FILE, "a" * 40 + "\n")
        self.ok("chore(parity): pin the spec")
        self.assertEqual(len(self.calls()), 1, "a commit of parity/SPEC_PIN was not judged by the tool")

    def test_test_harness_doc_commits_do_not_call_the_tool(self):
        self.point_hook_at(self.spec("judge"))
        self.put("docs/a.md", "a\n")
        self.ok("docs: a")
        self.red()
        self.put("tools/qa/y.py", "x = 1\n")
        self.ok("chore(harness): y" + HC)
        self.assertEqual(self.calls(), [])

    def test_test_harness_doc_commits_pass_without_a_spec(self):
        self.point_hook_at(Path(self.tmp) / "no-such-spec")
        self.put("docs/a.md", "a\n")
        self.ok("docs: a")
        self.red()
        self.put("tools/qa/y.py", "x = 1\n")
        self.ok("chore(harness): y" + HC)


@unittest.skipUnless(REAL_TOOL, "needs the laptop's zchat-spec clone with tools/parity.py on trunk")
class RealTool(ParityHookCase):
    """End to end: the real check-commit from a throwaway spec's trunk. Item PAR-0001 is zmsg, open on iOS."""

    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="iosgh-spec-")
        env = tg.env_for(cls.root)
        env.update(ZCHAT_PARITY_LOCK=str(Path(cls.root) / "parity.lock"),
                   ZCHAT_PARITY_CACHE=str(Path(cls.root) / "cache"),
                   ZCHAT_WAIVERS=str(Path(cls.root) / "WAIVERS_IOS.md"), ZCHAT_PARITY_BY="test")
        Path(env["ZCHAT_WAIVERS"]).write_text("# waivers\n\n## WI-9 — test approval\nOwner, verbatim: \"Yes\"\n")
        cls.spec_env = env
        cls.spec_dir = make_spec(Path(cls.root) / "spec", REAL_TOOL, env)

        def op(*args):
            r = subprocess.run([sys.executable, "-I", str(cls.spec_dir / "tools/parity.py"), "--spec",
                                str(cls.spec_dir), *args], env=env, capture_output=True, text=True, timeout=60)
            if r.returncode:
                raise AssertionError("fixture parity.py %s: %s%s" % (" ".join(args), r.stdout, r.stderr))
            return r.stdout

        op("init")
        for plat, ver, klass in [("android", "2.13.1", "outward"), ("android", "2.13.2", "outward"),
                                 ("ios", "0.1.0", "internal"), ("ios", "1.0.0", "outward"),
                                 ("backend", "2026.12", "outward")]:
            op("release", "add", "--platform", plat, "--version", ver, "--class", klass)
        op("area", "set", "--platform", "ios", "--pattern", "Packages/ZChatCore/Sources/ZChatProtocol/**",
           "--area", "zmsg", "--tier", "hard")
        for pat in ["Tests/**", "Packages/*/Tests/**", "App/Tests/**", "tools/qa/**", "docs/**", "parity/**",
                    "README.md"]:
            op("area", "exempt", "--platform", "ios", "--pattern", pat, "--reason", "tests, harness, docs or checks")
        out = op("add", "--kind", "wire", "--area", "zmsg", "--title", "A test behaviour", "--source", "W-236",
                 "--due", "ios=1.0.0", "--register", "ios=IOSP-4", "--case", "ios=zmsg/prefix.json#*",
                 "--null", "android", "--null", "backend")
        if "ADDED PAR-0001" not in out:
            raise AssertionError("fixture: expected ADDED PAR-0001, got %s" % out)
        op("validate")
        cls.pin = sh(cls.spec_dir, "rev-parse", "HEAD", env=env)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def setUp(self):
        super().setUp()
        self.point_hook_at(self.spec_dir)

    def test_open_item_trailer_passes(self):
        self.put(PIN_FILE, self.pin + "\n")
        self.put(PROTO, "public let prefix = \"ZMSG|\"\n")
        self.ok("refactor(protocol): x\n\nParity: PAR-0001")

    def test_no_trailer_blocked_with_the_tools_reason(self):
        self.put(PIN_FILE, self.pin + "\n")
        self.put(PROTO, "public let prefix = \"ZMSG|\"\n")
        self.closed("refactor(protocol): x", says="no Parity trailer")

    def test_unknown_item_blocked(self):
        self.put(PIN_FILE, self.pin + "\n")
        self.put(PROTO, "public let prefix = \"ZMSG|\"\n")
        self.closed("refactor(protocol): x\n\nParity: PAR-0099", says="unknown item PAR-0099")

    def test_missing_pin_blocked(self):
        self.put(PROTO, "public let prefix = \"ZMSG|\"\n")
        self.closed("refactor(protocol): x\n\nParity: PAR-0001", says="SPEC_PIN")

    def test_pin_only_commit(self):
        self.put(PIN_FILE, "f" * 40 + "\n")
        self.closed("chore(parity): pin the spec", says="does not hold the pinned commit")
        self.put(PIN_FILE, self.pin + "\n")
        self.ok("chore(parity): pin the spec")

    def test_weakened_tool_in_the_clone_changes_no_verdict(self):
        tool = self.spec_dir / "tools/parity.py"
        self.addCleanup(sh, self.spec_dir, "checkout", "-q", "-f", "trunk", env=self.spec_env)
        sh(self.spec_dir, "checkout", "-q", "-b", "weak-%s" % self._testMethodName, env=self.spec_env)
        tool.write_text("print('PARITY PASS: weakened on a branch')\n")
        sh(self.spec_dir, "commit", "-q", "-am", "weaken", env=self.spec_env)
        tool.write_text("print('PARITY PASS: weakened in the working tree')\n")
        self.put(PIN_FILE, self.pin + "\n")
        self.put(PROTO, "public let prefix = \"ZMSG|\"\n")
        out = self.closed("refactor(protocol): x", says="no Parity trailer")
        self.assertNotIn("weakened", out)

    def test_doc_and_test_commits_need_no_pin(self):
        self.put("docs/a.md", "a\n")
        self.ok("docs: a")
        self.red()


if __name__ == "__main__":
    unittest.main()
