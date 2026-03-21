# Part A: Recursive nonlocal propagation in symbol table

## Implementation Steps

1. **Make `_process_nested` recursive** in `src/skill_scan/_ast_symbol_table.py`
   - Current state: `_process_nested` (line 101) iterates `body` for FunctionDef/AsyncFunctionDef nodes but does NOT recurse into their bodies
   - Add recursive call: after processing an inner function's declarations, call `_process_nested` on its body to handle deeper nesting
   - **CRITICAL ordering**: recursion must happen BEFORE routing the current level's nonlocals. Process deepest nesting first so inner nonlocal writes land in `inner_scope`, then the current level's nonlocal routing propagates the accumulated value upward. Alternatively, re-route AFTER the recursive call returns.
   - File is at 290/300 lines. Budget ~5-8 lines for recursive call + ordering fix. May need to slim existing code to stay under 300.
   - The function currently calls `_route_nested_declarations` which pops from `inner_scope` and writes to `parent_scope`. For recursion to work, the recursive `_process_nested` call on the inner body must use `inner_scope` as the parent, so deeper nonlocals propagate into it BEFORE `_route_nested_declarations` moves values from `inner_scope` to `parent_scope`.

2. **Add tests** in `tests/unit/test_ast_symbol_table_scope.py`
   - Add `TestMultilevelNonlocal` class with cases:
     - 2-level nonlocal: inner -> outer -> grandparent
     - 3-level nonlocal chain: innermost -> inner -> outer
     - Global from deeply nested function routes to module scope
     - Mixed: nonlocal at level 2 + global at level 3

## Refined Criteria
- `_process_nested` calls itself recursively for nested FunctionDef/AsyncFunctionDef nodes
- Two-level nonlocal test: `def outer/def middle/def inner` with `nonlocal x` in inner updates `outer.x` (not `middle.x`)
- Three-level chain test: nonlocal propagates through 3 nesting levels
- Global from deeply nested routes to module scope (`result['x']` exists, `result.get('inner.x')` does not)
- `_ast_symbol_table.py` stays at or under 300 lines
- All existing tests in `test_ast_symbol_table_scope.py` still pass

## Dependencies Discovered
- `_collect_scope_declarations` at line 218 in `_ast_symbol_table_assignments.py` — already imported in `_process_nested`
- `_route_nested_declarations` at line 132 — handles global/nonlocal routing; must be called AFTER recursive `_process_nested` so inner values are accumulated first
- `_collect_return_value` used in `_process_nested` for return tracking — must be preserved
