# PLAN-034 Context

Accumulated knowledge, decisions, learnings, and blockers across execution sessions.

## Planning Phase

- Both debt items share the same root cause: no scope chain tracking
- `_collect_scope_declarations` already exists in `_ast_symbol_table_assignments.py` -- reusable for int-list tracker
- `_ast_symbol_table.py` at 290/300 lines -- Part A changes must be minimal
- `_ast_split_comprehension.py` at 281/300 lines -- Part B changes in this file must be minimal
- `_ast_split_int_list_tracker.py` at 118/300 lines -- ample room for scope declaration helpers
- User preference: bias toward inclusive detection (catch more) over minimizing false positives

## Part A Execution (2026-03-21)

- **Decision**: Recursive `_process_nested` call placed BEFORE `_route_nested_declarations` so deeper nonlocal writes accumulate in `inner_scope` before routing upward
- **Discovery**: Pass-through nonlocals needed — when `inner` declares `nonlocal x` but `middle` doesn't own `x`, the value must propagate past `middle`. Solved by tracking `own_keys` before recursion and routing new keys (that appeared via deeper recursion) upward only if they're also in `nonlocal_names`
- **Discovery**: Global from deeply nested already worked pre-change because `_route_nested_declarations` routes globals to `result` (module-level dict) regardless of nesting depth
- **DEBT**: `_ast_symbol_table.py` now at 297/300 lines — effectively frozen; any future addition requires extracting a helper to a sibling module
- **DEBT**: `_route_globals` and `_route_nested_declarations` share near-identical global-routing logic; worth merging if lines become available

## Part B Execution (2026-03-21)

- **Decision**: Added `_resolve_scope_key` as central scope-key builder in `_ast_split_int_list_tracker.py` and `_collect_fn_body` for nested function traversal with declaration awareness
- **Discovery**: Pass-through nonlocal required for int-list tracker too — `child_enc = enclosing if decls[1] else scope` handles chains correctly
- **Discovery**: E2E tests produce EXEC-002 findings (not OBFS-005) because the assembled 'eval' string matches EXEC-002 dangerous-name rule before split-evasion applies; tests use flexible assertions (`startswith("EXEC-") or startswith("OBFS-")`)
- **DRY fix**: Refactorer consolidated inline `f"{scope}.{name}" if scope else name` in `_resolve_binop_concat` and `_extend_with_tracked_var` to use `_resolve_scope_key`
- **Line counts**: tracker 198/300, comprehension 278/300, tests 293/300

## Documentation Step (2026-03-21)

- CLAUDE.md updated: new registration entries for `_resolve_scope_key`, `_collect_fn_body`; new invariants for recursive `_process_nested` and `_Decls` type alias; Known debt updated (`_ast_symbol_table.py` 297/300 frozen, corrected comprehension count to 278/300)
- ARCHITECTURE-REFERENCE.md updated: Symbol Table `_process_nested` description, Split-Evasion tracker and comprehension sub-module descriptions (line counts, new helpers)
- DEBT-021-NONLOCAL-MULTILEVEL and DEBT-028-INTLIST-GLOBAL-NONLOCAL resolved in debt.yaml (per plan)
