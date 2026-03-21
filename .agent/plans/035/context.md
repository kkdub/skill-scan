# PLAN-035 Context

Accumulated knowledge, decisions, learnings, and blockers across execution sessions.

## Planning Phase

- Two walkers exist: `_walk_fn_body` (tracker.py, with declarations) and `_collect_int_lists_from_body` (comprehension.py, without declarations)
- Both use `_sub_bodies` which returns `[stmt.body, stmt.orelse]` for If and `[case.body for case in stmt.cases]` for Match — walking them sequentially merges mutually exclusive branches
- `_ast_split_int_list_tracker.py` at 226/300 lines — 74 lines headroom for merge helper
- `_ast_split_comprehension.py` at 278/300 lines — 22 lines headroom, minimize changes here
- List values in result dict are never mutated in-place (always replaced), so shallow dict copy is sufficient for snapshots
- `_SHADOW` is a module-level sentinel compared by identity — merge logic must use `is` not `==` (since `_SHADOW == []` is True)
- `For`/`While` orelse and `Try`/`except` are NOT mutually exclusive — keep sequential walk for those
- `elif` chains are represented as nested `If` in `orelse` — handled correctly by recursive branch awareness

## Part A Execution (2026-03-21)

- build-and-test COMPLETE: Added `_values_agree`, `_merge_branches`, `_is_exhaustive_match` helpers; rewrote `_walk_fn_body` with If/Match snapshot/merge; `_collect_int_lists_from_body` removed — callers now call `_walk_fn_body` directly via `_collect_int_list_assigns`
- 3 existing tests updated to expect `_SHADOW` for if-only branch augassign patterns (old sequential behavior was incorrect)
- refine-and-confirm: no changes needed (DRY review clean)
- verify-and-fix: VERIFIED 13/13 criteria on first try
- Final line counts: tracker 294/300, comprehension 265/300
- 26 new tests in `test_int_list_branch_merge.py` covering all requirements + acceptance scenario

## Documentation Pass (2026-03-21)

- CLAUDE.md: project structure listing updated, test listing updated, registration entries added for `_walk_fn_body`, `_values_agree`, `_merge_branches`, `_is_exhaustive_match`; `_collect_fn_body` and `_collect_int_list_assigns` descriptions updated to reference `_walk_fn_body`; `_Decls` invariant extended; new branch-aware merge rule invariant added; Known debt line counts corrected (comprehension 265, tracker 294); DEBT-035-TRY-EXCEPT-BRANCH-MERGE recorded
- CODE-PATTERNS.md: new "Branch-Aware Int-List Body Walker" pattern added in Section 2
- plan.yaml: work_log docs entry + evidence added
- status.md: stale comprehension line count corrected; documentation note added
- handoff.yaml: final state written
