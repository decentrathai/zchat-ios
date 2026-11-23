# ZChat iOS orchestration — differences from the Android policy

Android's `docs/quality/ORCHESTRATION_POLICY.md` (v1.3, `/home/yourt/zchat-android`) governs who does what, the state
machine, severity and the git rules. This file holds only what differs for iOS, or what the iOS session must do the same
way and has to find here. Sources: W-110, W-103 (in `~/zchat-evidence/pm/WAIVERS.md`), WI-2 and WI-4 (in
`WAIVERS_IOS.md`), the Android session's process answers (`~/zchat-evidence/ios/FROM_ANDROID.md`, 22 Nov 19:29).

## Models per task (W-110; the owner's `~/.claude/CLAUDE.md`)
| Work | Model |
|---|---|
| Searches, web fetches, log reading, fact collection, vector porting, mechanical steps | Sonnet |
| RED tests, implementation, every money, key or format lane | Opus |
| Reviews, plan critiques, design, deep research | Fable |

The orchestrator passes `model` on every Agent call. The `ios-*` agent files carry the same model as their default
(`ios-reproducer` sonnet, `ios-red-test-author` and `ios-implementer` opus, `ios-reviewer` and `ios-plan-critic`
fable); that default works only once the agents load natively (a session opened in the WSL folder). Effort stays at the
session default unless the owner or a rule asks. A money change also gets a fresh small Opus recheck besides its
cross-family review.

**WI-4 window:** until 2026-11-22 23:00 CET Fable may be used without the usual limit; after that the split above applies.

**Budget without extra credits (owner, 23 Nov).** Fable is capped at half of the weekly limit and counts toward it. The
orchestrator runs on Opus; Fable is spent where a miss costs money or rework: plan critiques, reviews of guard, money,
crypto, privacy and format changes, and bugs still open after two tries. Fable resets are kept for the heaviest weeks
(the SDK and wallet port, the week before an upload review) and used only when Fable is near its cap early in a week,
never a day or two before the weekly reset. Subagents get short, scoped briefs; no many-agent workflows unless asked.

## Plan critique before work (W-103)
Before a plan changes code or harness (a lane, a harness change, a large refactor or test campaign): the plan is written
to `~/zchat-evidence/ios/plans/<PLAN>.md`, the `ios-plan-critic` (Fable) critiques it, the critique is saved beside it as
`<PLAN>_FABLE_CRITIQUE.md`, the plan is revised (`_v2`), and the commits cite it in `[harness-change: …]` or the body.
Review of finished commits is separate (`REVIEW.md`).

## Cross-family review
Every P0/P1 money, crypto, privacy, migration or format change gets Fable plus another model family (GPT through
Android's `venice_review.py`, on a bundle that `secret_scan.py --summary files <folder>` passes), and is written but not
merged until the owner answers B9 (AGENTS.md rule 2). `base_sha` and `head_sha` go in the question itself; the returned
sha is checked against them.

**Second-family routes, in order (23 Nov):**
1. Pearl DeepSeek-V4.1-Flash, `PEARL_EFFORT=low`, `PEARL_MAX` about 48000 (`~/zchat-evidence/ios/reviews/pearl_review_ios.py`):
   about 1-2 cents a review, ledger `ops/pearl/ledger.jsonl`. V4-Pro and caps of 16k return empty content (all reasoning).
2. GPT or Grok on the owner's subscriptions: `~/zchat-evidence/second-opinion-20261002/ask.py --backend gpt|grok`
   (read_file-only sandbox; its memory gate needs 5 GB free Windows commit; zx stops at 110 s, so run it detached).
3. Venice GPT through the Android session, from its budget, only when it has balance.
**WI-10 fallback:** when no second family answers, a Fable `ios-reviewer` review counts, recorded as "same family, WI-10".
A review is bound to exact bytes: any later change to a reviewed file makes the review stale.

## Roles and their rules
Roles: `ios-reproducer`, `ios-red-test-author`, `ios-implementer`, `ios-reviewer`, `ios-plan-critic` (`.claude/agents/`).
They are named `ios-*` so the Android guard's role rules (which know only Gradle paths) never apply to them (Android
session, 22 Nov: fine). **Until the guard's iOS role rules land and the session runs with native hooks, the role
boundaries are cooperative:** the agent files say them, nothing enforces them yet (`zx.py` cannot prove who calls it).
Role status words as Android: `REPRODUCED`, `RED_TEST_CONFIRMED`, `INDEPENDENT_REVIEWED`, `NOT_DONE`, `BLOCKED`.

## Session or subagent
A separate session for a long, independent lane with its own context (a worktree lane that runs for hours). A subagent
for a bounded task: one RED round, one implementation round, one review, one research question.

## Checking a subagent's evidence (never from its prose)
- Re-read every sha with `git log`, and `git merge-base --is-ancestor <red> HEAD` for each RED.
- Recount tests from the result files at the committed HEAD, not from the report; a timeout is never a pass.
- Confirm the RED fails for the stated reason at `red_test_sha`.
- `git diff --diff-filter=MDR <red_sha>..<head> -- <test paths>` is empty (no test changed after RED), and
  `git status --porcelain` is clean after each role.
- Check every finding against the live tree (`REVIEW.md` "After the review").

## What Android would not copy (FROM_ANDROID 22 Nov, point 5)
- Source-regex pins as the only proof of UI behaviour: use real UI tests where the platform allows.
- Money authorisations kept in contact-keyed slots: bind every quote, consent and allowance to the send attempt's id.
- One huge view model: split by flow from the start.
- Shell-parsing guard rules that refuse useful work: keep the guard to catastrophes and test every rule.
- Reused review templates with stale shas.
Copy: the register from day one, RED-first lineage, explicit pathspecs, two green runs on the frozen build, masking by
value.
