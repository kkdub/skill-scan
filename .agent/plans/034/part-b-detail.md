# Part B: Scope declaration tracking in int-list pre-pass

## Implementation Steps

1. **Add scope declaration awareness to int-list mutation helpers** in `src/skill_scan/_ast_split_int_list_tracker.py`
   - Add a `_resolve_scope_key(name, scope, declarations)` helper that resolves the correct target key based on global/nonlocal declarations:
     - If `name` is in `global_names`: return the bare `name` (module-level, empty scope)
     - If `name` is in `nonlocal_names`: return `enclosing_scope.name` (parent scope)
     - Otherwise: return `scope.name` (current scope, existing behavior)
   - Update `_handle_int_list_stmt` to accept an optional `declarations` parameter and pass it through to `_handle_assign` and `_extend_tracked`
   - Update `_handle_assign` to use the resolved key from declarations
   - Update `_extend_tracked` to use the resolved key from declarations
   - File is at 119 lines — plenty of room

2. **Add nested function traversal to `_collect_int_list_assigns`** in `src/skill_scan/_ast_split_comprehension.py`
   - Currently (lines 33-40) only walks top-level FunctionDef/ClassDef bodies. Nested functions inside functions are never visited because `_sub_bodies` explicitly excludes FunctionDef/ClassDef.
   - Add recursion: after walking a function's body, iterate its body for FunctionDef/AsyncFunctionDef nodes and recurse with the enclosing function as parent scope.
   - Import `_collect_scope_declarations` from `_ast_symbol_table_assignments` and collect declarations for each function body.
   - Pass declarations to `_handle_int_list_stmt` so global/nonlocal names resolve to the correct scope key.
   - File is at 281/300 lines — changes must be very minimal (19 lines available).

3. **Add tests** in `tests/unit/test_ast_split_int_list_tracker.py`
   - Add test cases:
     - Function with `global codes` mutating module-level int-list via `+=`
     - Function with `global codes` mutating via `.extend()`
     - Nested function with `nonlocal codes` mutating enclosing function's int-list
     - Mixed: global int-list + local int-list in same function (no cross-contamination)
   - Verify via `_collect_int_list_assigns` that the correct scope key is updated.

## Refined Criteria
- `_handle_int_list_stmt` accepts and uses scope declaration info to resolve the correct target key for global-declared variables
- `_handle_assign` resolves global-declared names to module-level key (not function-scoped) for initial assignments like `global codes; codes = [101]`
- `_extend_tracked` resolves global-declared names to module-level key (empty-string scope) instead of function-scoped key
- `_extend_tracked` resolves nonlocal-declared names to enclosing function's scope key
- `_collect_int_list_assigns` recurses into nested FunctionDef bodies (not just top-level functions)
- Test: function with `global codes; codes += [101]` updates module-level key, not `funcname.codes`
- Test: nested function with `nonlocal codes; codes.extend([101])` updates enclosing scope key
- `_ast_split_int_list_tracker.py` and `_ast_split_comprehension.py` stay at or under 300 lines
- All existing tests in `test_ast_split_int_list_tracker.py` still pass

## Dependencies Discovered
- `_collect_scope_declarations` at line 218 in `_ast_symbol_table_assignments.py` — reusable for collecting global/nonlocal declarations
- `_sub_bodies` in `_ast_symbol_table_returns.py` explicitly excludes FunctionDef/ClassDef — nested function traversal must happen separately
- `_handle_int_list_stmt` is the single dispatch point called from `_collect_int_lists_from_body` — adding declarations parameter here propagates to all mutation handlers
- Part A's recursive nonlocal propagation only affects the symbol table, not the int-list pre-pass — both need independent scope handling

## From Part A Context
- `_ast_symbol_table.py` is at 297/300 lines — do NOT touch it
- Pass-through nonlocal pattern (Part A discovery): when inner declares `nonlocal x` but middle doesn't own `x`, the value must propagate past middle. The int-list tracker needs similar logic if supporting multi-level nonlocal, but the plan criteria only require single-level nonlocal tracking.
