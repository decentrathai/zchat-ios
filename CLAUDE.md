# ZChat for iOS — Claude Code brief
@AGENTS.md
The plan: ~/zchat-evidence/ios-plan/IOS_PLAN_FINAL.md and its binding annexes in IOS_PLAN_FINAL_APPENDIX.md.
Orchestration, models per task, plan critiques and evidence checks: `docs/quality/ORCHESTRATION_IOS.md`. Reviews: `REVIEW.md`.

## Commands
| What | Command |
|---|---|
| Harness health and canaries (every start and harness change) | `tools/qa/doctor.sh --canary` |
| Harness tests | `python3 -m unittest discover -s tools/qa/tests` |
| Guarded command from a session without hooks (WI-2) | `python3 -I tools/qa/zx.py bash "<cmd>"` |
| Repo git hooks (run by the owner's chain) | `tools/qa/githooks/commit-msg`, `tools/qa/githooks/pre-commit` |
| Role agents | `.claude/agents/` |
| Parity registry (spec repo) | `python3 -I ~/zchat-spec/tools/parity.py validate` |

Not yet: `verify.sh`, `local_gates.py`, Swift builds (none before Android's "free" entry, AGENTS.md rule 12).

## Things Claude gets wrong
- A pipe hides a failing test from `set -e`: use `set -o pipefail` and stop on a red run before committing.
- A tag named in a commit message's prose (`[harness-change:]`) is not the tag: write the real one in full.
