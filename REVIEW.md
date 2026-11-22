# REVIEW.md — how ZChat iOS changes are reviewed

For every reviewer: the `ios-reviewer` subagent, independent Claude reviewers, and cross-family models (GPT through
Android's `venice_review.py`, Grok through `ask.py`) that get a sanitized bundle. Adapted from Android's `REVIEW.md`;
where a rule is the same, that file governs. The orchestrator re-checks every finding against the tree before anyone
acts on it.

## Inputs you review against
- The exact range: `git diff <base_sha>...<head_sha>` and the files it touches, read at the head with
  `git show <head_sha>:<path>`. **The question itself names `base_sha` and `head_sha`** (a reused bundle header once
  carried a stale sha: Android ZC-2631); your output names them again; a later commit makes the review STALE.
- The intent: the registry item (`parity.py show PAR-#### --masked`), the plan section it implements
  (`~/zchat-evidence/ios-plan/IOS_PLAN_FINAL.md`, annexes), and the RED test commit (`red_test_sha`), which states
  what "done" means.
- Android 2.13.1 is the reference for every byte the app sends or reads (AGENTS.md rule 4) and for the money and key
  rules (rules 5 to 7, Android skill `money-path`).

## Pass 1 — bugs and logic
- Root cause or symptom? Does the change hold for every caller, not only the one the test drives?
- Concurrency and lifecycle: actor isolation, a task cancelled before its work ends, two sends or two syncs racing, a
  value written but not read back after a relaunch, a migration that runs twice.
- Error paths: a decode, parse or SDK error that crashes, is swallowed, or turns into the wrong user state.
- Does the RED test fail at `red_test_sha` for the stated reason and pass at `head_sha` without being weakened? Is
  `git diff --diff-filter=MDR <red_sha>..<head_sha> -- <test paths>` empty?

## Pass 2 — money, keys, privacy and security
- Money: quote first and never above it; Retry pays once; automatic spends only with durable consent; status from
  notes; zatoshi are integers; a submit needs a `SpendPermit`; an interrupted send is resent as the same bytes. List
  every pay-to address the diff adds or changes (first 10 / last 8).
- Keys: every key is derived from the phrase; one file is the only door to the Keychain; nothing synchronizable; no
  `SecureEnclave.` in `ZChatCore`; phrase and PIN never reach a log, screenshot or clipboard.
- Privacy: no plaintext, key, seed, PIN, address or txid in logs, crash reports or relay events.
- Security: inputs from the chain or relays are bounded and typed; a new store is covered by Destroy.

## Pass 3 — compliance with the spec, the plan and parity
- **Parity:** the commit names an open `PAR-####` that covers every path it touches (or is the tool's sync commit), and
  the bytes match Android's vectors in both directions.
- **Peers:** an Android 2.13.1 or 2.12.4 phone still reads what iOS sends, and iOS reads what they send.
- The diff does what the item and the plan say, and nothing else. Scope beyond the plan is a finding even when correct.
- Texts: EN and ES keys and wording as Android; a money or privacy text says what really happens.

## Severity
**Important** (P0/P1) — the change can:
- lose funds or pay more than the user was shown (a second payment on Retry, an automatic spend without consent);
- lose or fail to restore a key, message, contact or chat history; reuse a send counter after a restore;
- leak private data (plaintext, keys, seed, PIN, addresses, txids, IP-linked metadata beyond the texts);
- show a false money status (sent, paid, failed, balance, fee) the notes do not support;
- break Android 2.13.1 or 2.12.4 peers, or drift from a shared vector;
- weaken a test or a check: a deleted or loosened assertion, a skipped test, an added known-issue marker, a guard, hook
  or scan rule made narrower.

**Normal** (P2) — a real defect with a workaround, or a missing test for a changed branch.
**Nit** (P3) — naming, comments, small simplifications. At most 5 nits.

## Do not report
- Formatting: swift-format and SwiftLint run in `verify.sh` once they exist.
- Generated files and build output (`.build/`, the Xcode project, which is generated from `project.yml`).
- Commit-message tokens the git hooks already check (subject format, `[red:]` and `[harness-change:]` present), and
  secret patterns the vendored scanner checks.
- Speculation without `path:line` and a scenario: put it under "Limitations".

## Output
Numbered findings, each: severity (Important / Normal / Nit, with P0–P3), `path:line` quoted from `head_sha`, the
scenario (inputs and state → wrong result), a fix direction, confidence. Then "Limitations". End with
`INDEPENDENT_REVIEWED` (no open Important) or `NOT_DONE`, plus `base_sha` and `head_sha`. Silence or praise is no pass.

## After the review (orchestrator)
- Each finding gets a verdict against the live tree: CONFIRMED, CONFIRMED-PREEXISTING, or REFUTED with the reason.
- A saved review lists its findings in one table: ID | Raised by | Finding | Verdict | Must-fix.
- Every CONFIRMED finding not fixed now goes into the register at once (`~/zchat-evidence/ios/REGISTER_PENDING.jsonl`
  until 2.13.1 has published, then `ki.py`; AGENTS.md rule 9).
- A kind of mistake seen twice gets one line in CLAUDE.md "Things Claude gets wrong" and, when a test can catch it, a
  check or a skill rule.
