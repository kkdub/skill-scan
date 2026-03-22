# Plan 036 Status

Terminal branch exclusion in int-list merge.

## Parts

| Part | Title | Status |
|------|-------|--------|
| a | _is_terminal_body helper module | Done |
| b | Wire _is_terminal_body into _walk_fn_body | Done |
| c | Integration tests for terminal branch exclusion | Pending |

## Key Findings

- (part-a) Exhaustive-match check reimplemented inline in `_ast_terminal_body.py` to avoid circular import
- (part-a) `_ast_terminal_body.py` at 109 lines — ample room
- (part-b) Tracker at exactly 300/300 lines — frozen for future additions
- (part-b) `_merge_branches([])` is no-op — both-terminal case needs no guard

## Current State

Parts a-b complete. Part c next — integration tests in test_int_list_branch_merge.py (91 lines of room).
