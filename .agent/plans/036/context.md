# Plan 036 Context

## Reality Check — Part A (2026-03-21)

Verified target file state:
- `_ast_split_int_list_tracker.py`: 296 lines (plan said 295 — 4 lines free, very tight)
- `_ast_symbol_table_returns.py`: 241 lines — `_definitely_returns` only checks `ast.Return`, not `ast.Raise`. Same recursive structure (`_stmt_definitely_returns`, `_if_definitely_returns`, etc.) confirms the plan's approach: mirror but check `Return | Raise`.
- `_sub_bodies` lives in `_ast_symbol_table_returns.py` (line 222), already imported deferred in `_walk_fn_body`.
- `_is_exhaustive_match` at line 211 of tracker — potential extraction target if line budget is exceeded in Part B.
- `test_int_list_branch_merge.py`: 210 lines, `_collect()` helper at line 16, established pattern.
- No `_ast_terminal_body.py` or `test_terminal_body.py` exist yet — clean creates.

No divergence from plan assumptions.

## Part A Complete (2026-03-21)

- `_ast_terminal_body.py` created: 109 lines, mirrors `_definitely_returns` structure with `Return | Raise` leaf check
- Exhaustive-match check reimplemented inline (avoids circular import with tracker)
- Uses `_sub_bodies` from `_ast_symbol_table_returns` for recursive traversal
- 41 tests, 12/12 criteria verified
- Refine: removed duplicate `_is_terminal_body(node.body)` call in `_try_is_terminal`
- R001, R002, R005, R-IMP001 marked done

## Part B Complete (2026-03-21)

- Tracker file at exactly 300/300 lines after changes
- `_merge_branches([])` is a no-op — both-terminal case works without an explicit guard (saves 2 lines)
- Ruff formatter expands list comprehensions with ternary — used imperative `if not terminal: append` pattern instead
- 15 tests in `test_terminal_branch_exclusion.py`, all pass
- R003, R004 partial (integration tests in Part C); R-IMP002 done
- DEBT: tracker file frozen at 300 lines — any future change requires extraction first

## Part C Complete (2026-03-21)

- 4 integration tests added to `TestTerminalBranchExclusion` class in `test_int_list_branch_merge.py`
- 5 duplicate tests removed (DRY dedup against Part B unit tests in `test_terminal_branch_exclusion.py`)
- `test_int_list_branch_merge.py` at 257/300 lines after additions
- `_ast_symbol_table_returns.py` updated: inline wildcard check replaced with import from `_ast_terminal_body`; tracker line count reduced to 291 after `_is_exhaustive_match` was extracted
- R003, R004 fully done; all requirements complete
- All parts Done; plan status set to Complete
