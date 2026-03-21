# Part A Detail: Branch-aware merge for If and Match in int-list pre-pass

## Implementation Steps

1. **Add `_merge_branches` helper to `_ast_split_int_list_tracker.py`**
   - Files: `src/skill_scan/_ast_split_int_list_tracker.py`
   - Takes N branch results (list of dicts) and merges conservatively into the result dict
   - For each key across all branch results:
     - Present in all branches with same value (by identity for `_SHADOW`, by `==` otherwise) -> keep
     - Present in some but not all branches, values agree -> keep value
     - Present in some but not all branches, values disagree -> shadow
     - Present in all branches with different values -> shadow
   - Must handle `_SHADOW` identity comparison correctly (`_SHADOW == []` is True)
   - Also need a snapshot-result helper or just use `result.copy()` (shallow copy sufficient since list values are never mutated in-place)

2. **Update `_walk_fn_body` to handle If and Match with snapshot/merge**
   - Files: `src/skill_scan/_ast_split_int_list_tracker.py`
   - Currently at lines 181-194, loops through `_sub_bodies` sequentially
   - When stmt is `ast.If`: snapshot result, walk `stmt.body`, capture after_if, restore snapshot, walk `stmt.orelse`, capture after_else, merge
   - When stmt is `ast.Match`: snapshot result, walk each `case.body` independently from snapshot, collect all branch results. For non-exhaustive match (no wildcard/`MatchAs(name=None)` case), include the snapshot itself as an extra branch. Then N-way merge.
   - For all other `_sub_bodies` results (For, While, Try, With): keep sequential walk
   - The `elif` chains are nested `If` in `orelse` — handled correctly by recursive snapshot/merge

3. **Update `_collect_int_lists_from_body` in `_ast_split_comprehension.py`**
   - Files: `src/skill_scan/_ast_split_comprehension.py` (278/300 lines, only 22 headroom!)
   - Currently at lines 37-46, uses `_sub_bodies` sequentially — same bug as `_walk_fn_body`
   - Must share the same branch-aware logic. Best approach: import `_walk_branch_aware_body` from tracker, or refactor `_walk_fn_body` to accept optional declarations and use it as the shared walker
   - Key insight: `_collect_int_lists_from_body` is just `_walk_fn_body` without declarations. If we make `_walk_fn_body` accept `decls=None` and `enclosing=""` as defaults, we can call it directly from `_collect_int_lists_from_body` as a one-liner, saving lines

4. **Add tests**
   - Files: `tests/unit/test_ast_split_int_list_tracker.py`
   - Test cases per plan criteria

## Refined Criteria
- `_walk_fn_body` handles `ast.If` by snapshotting, walking branches independently, and merging
- `_walk_fn_body` handles `ast.Match` by snapshotting, walking each case independently, and N-way merging
- Non-exhaustive match (no wildcard case) includes pre-match snapshot as extra merge branch
- `_collect_int_lists_from_body` uses the same branch-aware logic (not a separate code path)
- For/While/Try/With sub-bodies still walked sequentially (no snapshot/merge)
- Keys with identical values across all branches are retained
- Keys newly assigned in only one branch are preserved (security-conservative)
- Keys with different values across branches are replaced with `_SHADOW`
- `_SHADOW` comparison uses identity (`is`), not equality (`==`)
- Declaration threading (`_Decls`) works correctly through branch-aware paths
- All existing tests pass (`make check` green)
- `_ast_split_int_list_tracker.py` stays under 300 lines
- `_ast_split_comprehension.py` stays under 300 lines

## Dependencies Discovered
- `_sub_bodies` returns `[stmt.body, stmt.orelse]` for If — both body and orelse are always present (orelse is `[]` when no else clause)
- `_sub_bodies` returns `[case.body for case in stmt.cases]` for Match — need to check exhaustiveness via `MatchAs(name=None)` wildcard pattern
- `_collect_int_lists_from_body` is the same as `_walk_fn_body` minus declarations — can be unified
- Shallow dict copy sufficient for snapshots since list values are never mutated in-place (always replaced)
- Corpus file exists at `corpus/red-team/2026-03-17-full/split-kwargs-evasion/split_intlist_branch.py`
