#!/usr/bin/env bash
# doctor.sh [--canary]: health of the iOS harness (plan E.3). With --canary, runs tools/qa/canary.py and logs to
# ~/zchat-evidence/ios/canary.log. Prints one line per check; exit 1 on any failure.
set -u
R=$(cd "$(dirname "$0")/../.." && pwd)
fail=0
say() { printf '%s\n' "$*"; }
[ "$(git -C "$R" config core.hooksPath)" = /home/yourt/.config/zchat-denylist/hooks ] && say "hooksPath: ok" || { say "hooksPath: WRONG"; fail=1; }
[ -z "$(git config --global core.hooksPath)" ] && say "global hooksPath: unset (ok)" || { say "global hooksPath: SET"; fail=1; }
b=$(git -C "$R" symbolic-ref --short HEAD 2>/dev/null); case "$b" in main|master) say "branch: $b (FORBIDDEN)"; fail=1;; *) say "branch: $b";; esac
cmp -s "$R/AGENTS.md" "$HOME/zchat-evidence/ios-plan/IOS_SESSION_PROMPT_FINAL.md" && say "AGENTS.md: equals the session prompt" || say "AGENTS.md: differs from the session prompt (expected once it grows, A12)"
for f in TO_ANDROID.md FROM_ANDROID.md; do [ -e "$HOME/zchat-evidence/ios/$f" ] && say "mailbox $f: ok" || { say "mailbox $f: MISSING"; fail=1; }; done
[ -e "$HOME/zchat-evidence/pm/WAIVERS_IOS.md" ] && say "WAIVERS_IOS.md: ok" || { say "WAIVERS_IOS.md: MISSING"; fail=1; }
say "pre-push: not active (the owner's global pre-push does not chain; plan D.5)"
for h in commit-msg pre-commit; do [ -x "$R/tools/qa/githooks/$h" ] && say "repo hook $h: ok" || { say "repo hook $h: MISSING (the owner's chain skips it silently)"; fail=1; }; done
if (cd "$R/tools/qa/vendor" && grep -v '^#' VENDORED.lock | awk 'NF{print $1"  "$2}' | sha256sum -c --quiet >/dev/null 2>&1); then say "vendored scanners: equal VENDORED.lock"; else say "vendored scanners: CHANGED or MISSING"; fail=1; fi
g=$(git -C /home/yourt/zchat-android hash-object tools/qa/hooks/guard.py 2>/dev/null | cut -c1-12); say "android guard blob: ${g:-UNREADABLE}"
if [ "${1:-}" = "--canary" ]; then
  python3 "$R/tools/qa/canary.py" --log "$HOME/zchat-evidence/ios/canary.log" || fail=1
fi
[ $fail = 0 ] && say "DOCTOR OK" || say "DOCTOR FAILED"
exit $fail
