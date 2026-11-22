"""Tests for the iOS guard (plan E.3, annex A14). Run: python3 -m unittest discover -s tools/qa/tests -v

Every rule has a deny case and, where a near miss is plausible, an allow case, so the guard can neither fail open
nor block ordinary iOS work. The guard is called as Claude Code calls it: a PreToolUse payload on stdin.
"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
ENTRY = os.path.join(ROOT, "tools", "qa", "hooks", "guard_entry.py")
IOS = "/home/yourt/zchat-ios"
AND = "/home/yourt/zchat-android"


def decide(tool, tool_input, cwd=IOS):
    payload = {"session_id": "t", "transcript_path": "/dev/null", "cwd": cwd, "hook_event_name": "PreToolUse",
               "tool_name": tool, "tool_input": tool_input}
    r = subprocess.run([sys.executable, ENTRY], input=json.dumps(payload), capture_output=True, text=True,
                       timeout=30, env=dict(os.environ, CLAUDE_PROJECT_DIR=IOS))
    if r.returncode == 2:
        return "deny", r.stderr
    assert r.returncode == 0, r.stderr
    if not r.stdout.strip():
        return "allow", ""
    h = json.loads(r.stdout).get("hookSpecificOutput", {})
    return h.get("permissionDecision", "allow"), h.get("permissionDecisionReason", "")


def bash(cmd, cwd=IOS):
    return decide("Bash", {"command": cmd, "description": "t"}, cwd)[0]


class CrossTreeWrites(unittest.TestCase):
    def test_write_tool_into_android_denied(self):
        self.assertEqual(decide("Write", {"file_path": AND + "/x.kt", "content": "x"})[0], "deny")

    def test_edit_into_android_worktree_denied(self):
        self.assertEqual(decide("Edit", {"file_path": "/home/yourt/zchat-android-wt/es2132/a.kt",
                                         "old_string": "a", "new_string": "b"})[0], "deny")

    def test_multiedit_into_backend_denied(self):
        self.assertEqual(decide("MultiEdit", {"file_path": "/home/yourt/zchat/apps/backend/src/a.ts",
                                              "edits": []})[0], "deny")

    def test_write_into_backend_worktrees_and_configs_denied(self):
        for p in ("/home/yourt/zchat-worktrees/noip/a.ts", "/home/yourt/.config/zchat-qa/devices.json",
                  "/home/yourt/.config/zchat-denylist/hooks/pre-commit", "~/zchat-android/AGENTS.md",
                  "/home/yourt/zchat-ios/../zchat-android/x"):
            self.assertEqual(decide("Write", {"file_path": p, "content": "x"})[0], "deny", p)

    def test_write_into_own_trees_allowed(self):
        for p in (IOS + "/Packages/ZChatCore/Sources/a.swift", "/home/yourt/zchat-spec/spec/x.md",
                  "/home/yourt/zchat-evidence/ios/STATUS.md", "/home/yourt/zchat-ios-wt/m1/a.swift",
                  "/home/yourt/zchat-iosx/a"):
            self.assertEqual(decide("Write", {"file_path": p, "content": "x"})[0], "allow", p)

    def test_zchat_prefix_is_not_zchat_ios(self):
        self.assertEqual(decide("Write", {"file_path": "/home/yourt/zchat/x", "content": "x"})[0], "deny")
        self.assertEqual(decide("Write", {"file_path": IOS + "/x", "content": "x"})[0], "allow")

    def test_bash_redirect_cp_mv_rm_into_android_denied(self):
        for c in ("echo x > /home/yourt/zchat-android/a", "echo x >> ~/zchat-android/a",
                  "cp a.swift /home/yourt/zchat-android/", "mv ~/zchat-android/a /tmp/a",
                  "rm -rf /home/yourt/zchat-android-wt/es2132/app", "tee $HOME/zchat-android/x < y",
                  "sed -i s/a/b/ /home/yourt/zchat-android/a.kt", "touch /home/yourt/zchat/a",
                  "mkdir -p ~/.config/zchat-qa/x", "dd if=a of=/home/yourt/zchat-android/b"):
            self.assertEqual(bash(c), "deny", c)

    def test_bash_relative_write_after_cd_denied(self):
        self.assertEqual(bash("cd /home/yourt/zchat-android && echo x > a.txt"), "deny")
        self.assertEqual(bash("echo x > a.txt", cwd=AND), "deny")
        self.assertEqual(bash("cd ~/zchat-android; git commit -m x"), "deny")

    def test_bash_git_write_in_android_denied(self):
        for c in ("git -C /home/yourt/zchat-android commit -m x", "git -C ~/zchat-android-wt/es2132 checkout dev",
                  "git -C /home/yourt/zchat-android worktree add /tmp/w", "git -C /home/yourt/zchat stash",
                  "git -C /home/yourt/zchat-android apply p.patch"):
            self.assertEqual(bash(c), "deny", c)

    def test_bash_reads_of_android_allowed(self):
        for c in ("cat /home/yourt/zchat-android/AGENTS.md", "git -C /home/yourt/zchat-android log --oneline -3",
                  "grep -rn ZMSG /home/yourt/zchat-android-wt/es2132/app | head",
                  "git -C ~/zchat-android-wt/es2132 show HEAD:AGENTS.md > /home/yourt/zchat-evidence/ios/a.md",
                  "cd /home/yourt/zchat-android && git status --short", "ls ~/.config/zchat-qa",
                  "cp /home/yourt/zchat-android/AGENTS.md /home/yourt/zchat-evidence/ios/a.md",
                  "git -C /home/yourt/zchat-android archive HEAD | tar -x -C /home/yourt/zchat-evidence/ios/src"):
            self.assertEqual(bash(c), "allow", c)

    def test_heavy_and_parity_lock_allowed(self):
        self.assertEqual(bash("/home/yourt/zchat-android/tools/qa/heavy.py --holder 'ios x' -- swift build"),
                         "allow")
        self.assertEqual(bash("flock ~/.config/zchat-qa/locks/parity.lock python3 tools/parity.py validate",
                              cwd="/home/yourt/zchat-spec"), "allow")

    def test_sdk_fork_allowed_other_sdk_trees_denied(self):
        self.assertEqual(decide("Write", {"file_path": "/home/yourt/zchat-nu7-sdk/zcash-swift-wallet-sdk/a.swift",
                                          "content": "x"})[0], "allow")
        self.assertEqual(decide("Write", {"file_path": "/home/yourt/zchat-nu7-sdk/librustzcash/a.rs",
                                          "content": "x"})[0], "deny")


class Publishing(unittest.TestCase):
    def test_upload_commands_denied(self):
        for c in ("fastlane pilot upload", "bundle exec fastlane deliver", "fastlane upload_to_testflight",
                  "fastlane ios upload_to_app_store", "xcrun altool --upload-app -f a.ipa",
                  "xcrun altool --upload-package a.ipa", "gh release create v1", "gh workflow run upload.yml",
                  "gh workflow run core-macos.yml", "gh repo edit --visibility public",
                  "gh repo create zchat-ios --public", "git remote set-url origin git@github.com:x/y.git",
                  "git push https://github.com/x/y.git dev", "git push --no-verify origin dev",
                  "git commit --no-verify -m x", "git -c core.hooksPath=/tmp/h commit -m x",
                  "git config core.hooksPath /tmp/h"):
            self.assertEqual(bash(c), "deny", c)

    def test_ordinary_git_allowed(self):
        for c in ("git status", "git add -A", "git commit -m 'test(spec): x'", "git log --oneline",
                  "git config core.hooksPath", "gh run list", "gh run view 123 --log"):
            self.assertEqual(bash(c), "allow", c)


class GitHubControlsAndBilling(unittest.TestCase):
    def test_secret_and_controls_denied(self):
        for c in ("gh secret set ASC_KEY < k", "gh secret delete X", "gh variable set X --body y",
                  "gh api -X PUT repos/o/r/environments/prod", "gh api --method POST repos/o/r/keys -f key=x",
                  "gh api repos/o/r/branches/dev/protection -X DELETE",
                  "gh api -X POST repos/o/r/actions/runs/1/pending_deployments",
                  "gh api -X PATCH /user/settings/billing/budgets/1", "gh api repos/o/r/rulesets -f name=x",
                  "gh api -X PUT repos/o/r/actions/permissions/workflow"):
            self.assertEqual(bash(c), "deny", c)

    def test_read_api_allowed(self):
        self.assertEqual(bash("gh api repos/o/r/actions/runs"), "allow")
        self.assertEqual(bash("gh api repos/o/r/environments"), "allow")


class SigningAndSecrets(unittest.TestCase):
    def test_signing_files_denied(self):
        for p in ("/home/yourt/k/AuthKey_ABC.p8", "/a/dist.p12", "/a/x.mobileprovision", "/a/c.cer",
                  "/home/yourt/zchat-ios/fastlane/.env.default"):
            self.assertEqual(decide("Read", {"file_path": p})[0], "deny", p)
            self.assertEqual(decide("Write", {"file_path": p, "content": "x"})[0], "deny", p)
        for c in ("cat AuthKey_ABC.p8", "base64 dist.p12", "security find-generic-password -s x -w",
                  "security export -k login.keychain", "openssl pkcs12 -in dist.p12"):
            self.assertEqual(bash(c), "deny", c)

    def test_swift_source_named_like_cert_allowed(self):
        self.assertEqual(decide("Read", {"file_path": IOS + "/Packages/ZChatPlatform/Sources/Certs.swift"})[0],
                         "allow")


class ParityFiles(unittest.TestCase):
    def test_direct_edit_of_parity_files_denied(self):
        for p in ("/home/yourt/zchat-spec/parity/PARITY.json", "/home/yourt/zchat-spec/parity/PARITY.log",
                  "/home/yourt/zchat-spec/parity/areas.json", "/home/yourt/zchat-spec/parity/texts/map.json",
                  IOS + "/parity/SPEC_PIN", IOS + "/parity/VECTORS.lock", "/home/yourt/zchat-ios-wt/m1/parity/x"):
            self.assertEqual(decide("Write", {"file_path": p, "content": "x"})[0], "deny", p)
        self.assertEqual(bash("echo '{}' > /home/yourt/zchat-spec/parity/PARITY.json"), "deny")
        self.assertEqual(bash("sed -i s/a/b/ parity/PARITY.json", cwd="/home/yourt/zchat-spec"), "deny")

    def test_parity_tool_and_spec_text_allowed(self):
        self.assertEqual(bash("python3 tools/parity.py add --kind wire", cwd="/home/yourt/zchat-spec"), "allow")
        self.assertEqual(decide("Write", {"file_path": "/home/yourt/zchat-spec/tools/parity.py",
                                          "content": "x"})[0], "allow")
        self.assertEqual(decide("Read", {"file_path": "/home/yourt/zchat-spec/parity/PARITY.json"})[0], "allow")


class ServersLicencesThirdParty(unittest.TestCase):
    def test_ssh_denied(self):
        for c in ("ssh root@203.0.113.5", "scp a host:/b", "rsync -a a host:/b", "sftp host"):
            self.assertEqual(bash(c), "deny", c)

    def test_forbidden_packages_denied(self):
        for dep in ('.package(url: "https://github.com/zodl-inc/zodl-swift-sdk", exact: "1.0.0")',
                    '.package(url: "https://github.com/signalapp/libsignal", exact: "0.1.0")',
                    '.package(url: "https://github.com/x/slipstream", exact: "1.0.0")'):
            self.assertEqual(decide("Write", {"file_path": IOS + "/Packages/ZChatWallet/Package.swift",
                                              "content": "let p = [" + dep + "]"})[0], "deny", dep)
        self.assertEqual(decide("Write", {"file_path": IOS + "/Packages/ZChatCore/Package.swift",
                                          "content": '.package(url: "https://github.com/apple/swift-crypto", '
                                                     'exact: "3.10.0")'})[0], "allow")

    def test_running_code_in_thirdparty_denied(self):
        tp = "/home/yourt/zchat-evidence/ios/thirdparty/sdk@abc"
        for c in ("swift build", "make", "./build.sh", "cargo test", "bash x.sh", "npm install"):
            self.assertEqual(bash(c, cwd=tp), "deny", c)
            self.assertEqual(bash("cd " + tp + " && " + c), "deny", c)
        self.assertEqual(bash("cd " + tp + " && cat Package.swift"), "allow")
        self.assertEqual(bash("git -C " + tp + " log -1"), "allow")


class FailClosed(unittest.TestCase):
    def test_garbage_payload_denied(self):
        r = subprocess.run([sys.executable, ENTRY], input="not json", capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_unknown_tool_allowed(self):
        self.assertEqual(decide("Glob", {"pattern": "**/*.swift"})[0], "allow")


if __name__ == "__main__":
    unittest.main()
