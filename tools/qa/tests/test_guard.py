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


class Bypasses(unittest.TestCase):
    """Ways around the floor rules found in the first review (2026-11-22)."""

    def test_flock_prefix_does_not_hide_the_command(self):
        for c in ("flock ~/.config/zchat-qa/locks/parity.lock rm -rf ~/zchat-android",
                  "flock -w 5 /tmp/l gh secret set X < k",
                  "flock /tmp/l -c 'echo x > ~/zchat-android/a'"):
            self.assertEqual(bash(c), "deny", c)

    def test_nested_shells_and_eval_are_parsed(self):
        for c in ("bash -c 'echo x > ~/zchat-android/a'", "sh -c \"rm -rf /home/yourt/zchat/apps\"",
                  "eval 'git -C /home/yourt/zchat-android commit -m x'", "bash -lc 'gh secret set X < k'",
                  "timeout 5 bash -c 'touch /home/yourt/zchat-android-wt/x'"):
            self.assertEqual(bash(c), "deny", c)
        self.assertEqual(bash("bash -c 'ls ~/zchat-android'"), "allow")

    def test_pushd_moves_the_directory(self):
        self.assertEqual(bash("pushd ~/zchat-android && git commit -m x"), "deny")
        self.assertEqual(bash("pushd ~/zchat-android && echo x > a"), "deny")

    def test_git_env_repo_is_seen(self):
        self.assertEqual(bash("GIT_DIR=/home/yourt/zchat-android/.git git commit -m x"), "deny")
        self.assertEqual(bash("GIT_WORK_TREE=/home/yourt/zchat-android git checkout -- ."), "deny")
        self.assertEqual(bash("export GIT_DIR=/home/yourt/zchat-android/.git; git commit -m x"), "deny")

    def test_target_directory_and_find_writers(self):
        for c in ("cp -t ~/zchat-android a.swift", "mv --target-directory=/home/yourt/zchat-android a",
                  "find ~/zchat-android -name x -delete", "find /home/yourt/zchat-android -exec rm {} +",
                  "xargs rm < list.txt; rm ~/zchat-android/x"):
            self.assertEqual(bash(c), "deny", c)
        self.assertEqual(bash("find ~/zchat-android -name '*.kt' -newer x"), "allow")

    def test_graphql_mutation_denied(self):
        self.assertEqual(bash("gh api graphql -f query='mutation { updateRepository(input:{}) { clientMutationId } }'"),
                         "deny")
        self.assertEqual(bash("gh api graphql -f query='query { viewer { login } }'"), "allow")


class ReviewBypasses(unittest.TestCase):
    """Fable review of b943758 (2026-11-22): every allowed payload it found must now deny."""

    def assertDeny(self, cmds, cwd=IOS):
        for c in cmds:
            self.assertEqual(bash(c, cwd), "deny", repr(c))

    def assertAllow(self, cmds, cwd=IOS):
        for c in cmds:
            self.assertEqual(bash(c, cwd), "allow", repr(c))

    def test_newlines_and_heredocs(self):
        self.assertDeny(["echo start\nrm -rf /home/yourt/zchat-android/app/build",
                         "cd ~/zchat-android\ngit commit -am x", "echo go\ngh secret set X --body y",
                         "echo go\ngit push https://github.com/x/y.git dev",
                         "bash <<'EOF'\nrm -rf ~/zchat-android/x\nEOF",
                         "python3 - <<'EOF'\nimport shutil; shutil.rmtree('/home/yourt/zchat-android/x')\nEOF",
                         "echo a \\\n && rm -rf ~/zchat-android/x"])
        self.assertAllow(["cat > /home/yourt/zchat-evidence/ios/n.md <<'EOF'\nIt's done\nEOF",
                          "echo a\necho b > /home/yourt/zchat-evidence/ios/b.txt"])

    def test_fd_numbers_and_trailing_options(self):
        self.assertDeny(["cp a.swift /home/yourt/zchat-android/ 2>/dev/null",
                         "rsync -a src/ ~/zchat-android/ 2>&1 | tail",
                         "rsync -a src/ ~/zchat-android/ --exclude .git",
                         "cp f ~/zchat-spec/parity/PARITY.json 2>&1", "cmd >& ~/zchat-android/log",
                         "cp --target-directory ~/zchat-android a"])

    def test_shell_keywords(self):
        self.assertDeny(["for d in app lib; do rm -rf ~/zchat-android/$d/build; done",
                         "if [ -f x ]; then git -C ~/zchat-android stash; fi", "test -f k || { gh secret set X < k; }",
                         "while true; do touch ~/zchat-android/x; done", "! rm ~/zchat-android/x"])

    def test_in_place_flags(self):
        self.assertDeny(["perl -pi -e 's/a/b/' /home/yourt/zchat-android/a.kt",
                         "sed -Ei 's/a/b/' ~/zchat-spec/parity/PARITY.json", "sed -ni p ~/zchat-android/a",
                         "sed 's/a/b/w /home/yourt/zchat-android/out' x"])

    def test_publish_lanes(self):
        self.assertDeny(["bundle exec fastlane beta", "fastlane ios release",
                         "xcodebuild -exportArchive -archivePath a -exportOptionsPlist up.plist"])
        self.assertAllow(["grep -n deliver fastlane/Fastfile", "git commit -m 'ci: document fastlane pilot lane'",
                          "ls Sources/Transporter"])

    def test_variables_globs_parents_substitutions(self):
        self.assertDeny(["A=/home/yourt/zchat-android; echo x > $A/notes.md",
                         "A=/home/yourt/zchat-android; cd $A && git commit -m x",
                         "rm -rf ~/zchat-android*/build", "rm -rf /home/yourt/zchat-*/tmp", "rm -rf ~/.config",
                         "X=\"$(cd ~/zchat-android && git stash)\"", "X=`rm -rf ~/zchat-android/x`",
                         "echo x > //home/yourt/zchat-android/a", "echo x > ~yourt/zchat-android/a",
                         "rm -rf /home/yourt", "mv ~/zchat-worktrees /tmp/x"])

    def test_signing_reads(self):
        self.assertDeny(["cd fastlane && cat .env", "base64 < AuthKey_ABC.p8", "cat < fastlane/.env",
                         "find . -name '*.p8' -exec cat {} \\;", "git show HEAD:fastlane/.env", "git add -f dist.p12"])
        self.assertEqual(decide("Grep", {"pattern": "KEY", "path": IOS + "/fastlane"})[0], "deny")
        self.assertEqual(decide("Grep", {"pattern": "KEY", "glob": "*.p8"})[0], "deny")

    def test_hook_bypass_and_push_targets(self):
        self.assertDeny(["git commit -m x -n", "git commit -a -n -m x", "git commit -nm x",
                         "git config --unset-all core.hooksPath",
                         "git config remote.origin.pushurl https://github.com/x/y.git",
                         "git config remote.origin.url git@github.com:x/y.git",
                         "git push --repo=https://github.com/x/y.git", "git push github.com:x/y.git dev"])
        self.assertAllow(["git push origin dev", "git config --get remote.origin.url"])

    def test_github_controls(self):
        self.assertDeny(["gh api -XPUT repos/o/r/environments/prod", "gh api repos/o/r/keys --field=key=x",
                         "gh api repos/o/r/keys --input=f", "gh api repos/o/r/keys -fkey=x",
                         "gh api -X PATCH repos/o/r/actions/variables/X -f value=y",
                         "gh api -X PATCH repos/o/r -f private=false", "gh api -X PATCH repos/o/r -f visibility=public",
                         "gh repo deploy-key add k.pub", "gh secret -R o/r set X"])
        self.assertAllow(["gh api repos/o/r/actions/runs?per_page=5", "gh run list -L 5"])

    def test_more_writers_and_git(self):
        self.assertDeny(["curl -o ~/zchat-android/x https://example.com/a", "wget -O /home/yourt/zchat-android/x u",
                         "wget -P ~/zchat-android u", "patch -d ~/zchat-android -p1 < p",
                         "patch ~/zchat-android/a.kt < p", "tar xf a.tar --directory=~/zchat-android",
                         "tar -xC ~/zchat-android -f a.tar", "cd ~/zchat-android && unzip a.zip",
                         "git -C ~/zchat-android format-patch -1", "git -C ~/zchat-android bisect start",
                         "git -C ~/zchat-android checkout-index -a", "git -C ~/zchat-android symbolic-ref HEAD x",
                         "git --git-dir ~/zchat-android/.git commit -m x",
                         "git clone --depth 1 https://x/y ~/zchat-android/x",
                         "git worktree add -b br ~/zchat-android-wt/x", "git -C ~/zchat-android fetch"])

    def test_reading_android_still_allowed(self):
        self.assertAllow(["find ~/zchat-android -name '*.kt' -exec grep -l ZMSG {} +",
                          "git -C ~/zchat-android branch --all", "git -C ~/zchat-android branch -a --contains abc123",
                          "git -C ~/zchat-android tag -l", "(cd ~/zchat-android && git log -1); echo x > out.txt",
                          "ln -s ~/zchat-android/AGENTS.md /home/yourt/zchat-evidence/ios/ref.md",
                          "git -C ~/zchat-android log --format=%H -1 | head -c 9",
                          "sha256sum ~/zchat-android/AGENTS.md", "diff ~/zchat-android/a ~/zchat-ios/b",
                          "awk '{print $1}' ~/zchat-android/x", "wc -l ~/zchat-android/app/src/main/x.kt"])


class FailClosed(unittest.TestCase):
    def test_garbage_payload_denied(self):
        r = subprocess.run([sys.executable, ENTRY], input="not json", capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_unknown_tool_allowed(self):
        self.assertEqual(decide("Glob", {"pattern": "**/*.swift"})[0], "allow")


if __name__ == "__main__":
    unittest.main()
