# Red-Team Report

**Target:** `src/skill_scan/_ast_kwargs_detector.py` (detect_kwargs_unpacking)
**Domain:** Security scanner -- detecting dangerous kwargs (shell=True) via dict unpacking
**Logic reviewed:** `_ast_kwargs_detector.py` lines 1-298, `ast_analyzer.py` lines 1-115
**Claim tested:** R-EFF001 -- shell='0' (truthy string) no longer false-negative; 0% false-negative rate on truthy values passed as dangerous kwargs

## Attack Surface Summary

The detector has three resolution paths for dict values:

1. **_extract_dict_literal** (line 252-268) -- extracts from inline `ast.Dict` nodes; only handles `ast.Constant` value nodes
2. **_track_subscript_assign** (line 174-191) -- tracks `opts['shell'] = val`; requires `isinstance(value, ast.Constant)`
3. **_lookup_symbol_table_dict** (line 271-279) -- reconstructs from symbol table (string-only); this path coerces all values to strings

The `_kwarg_matches` function (line 282-297) correctly uses `bool()` truthiness for boolean table entries. The truthiness logic itself is sound.

**Critical gap:** Paths 1 and 2 both filter on `isinstance(node, ast.Constant)`. On Python 3.13, negative numeric literals (`-1`, `-1.0`) are represented as `ast.UnaryOp(USub, Constant(N))`, and complex expressions like `(1+0j)` are `ast.BinOp(Add, Constant(1), Constant(0j))`. Neither is `ast.Constant`, so these entries are silently dropped from the extracted dict -- the key simply does not exist, and `_kwarg_matches` returns False (key not found).

## Adversarial Corpus Generated
- Total inputs: 85 test cases
- Categories: 14 (truthy strings, truthy non-strings, falsy guards, tracked dicts, dict unions, symbol table coercion, structural, import aliasing, kwarg_matches unit, full pipeline, type preservation, resolution priority, negative int AST, edge cases)
- Saved to: `corpus/red-team/2026-03-16/adversarial_kwargs_corpus.py`

## Evasion Results

| Category                     | Inputs | Evaded | Rate  |
|------------------------------|--------|--------|-------|
| Truthy string evasion        | 10     | 0      | 0%    |
| Truthy non-string evasion    | 6      | 3      | 50%   |
| Falsy values (FP guard)      | 6      | 0      | 0%    |
| Tracked dict truthy evasion  | 5      | 1      | 20%   |
| Dict union truthy evasion    | 4      | 0      | 0%    |
| Symbol table coercion        | 3      | 0      | 0%    |
| Structural evasion           | 12     | 0      | 0%    |
| Import aliasing evasion      | 4      | 0      | 0%    |
| _kwarg_matches adversarial   | 12     | 0      | 0%    |
| Full pipeline truthy evasion | 6      | 1      | 17%   |
| Type preservation            | 8      | 0      | 0%    |
| Resolution path priority     | 2      | 0      | 0%    |
| Negative int AST parsing     | 2      | 0      | 0%    |
| Edge cases                   | 7      | 0      | 0%    |
| **Total**                    | **85** | **5**  | **5.9%** |

## Critical Findings

### 1. Negative Number Evasion via ast.UnaryOp (50% evasion in category)

**Severity:** CRITICAL -- trivial to exploit, complete detection bypass

**Root cause:** `_extract_dict_literal` (line 263-267) and `_track_subscript_assign` (line 185-186) only accept `ast.Constant` value nodes. On Python 3.13, negative numeric literals are `ast.UnaryOp(USub, Constant)`, not `ast.Constant`.

**Evasion technique:** Use any negative number as the `shell` value:
```python
subprocess.run(cmd, **{'shell': -1})  # -1 is truthy, EVADES detection
```

**Scope of evasion:** ALL negative numbers evade across ALL resolution paths:
- Inline dict literal: `**{'shell': -1}` -- EVADES
- Tracked dict literal: `opts = {'shell': -1}; run(**opts)` -- EVADES
- Subscript assignment: `opts['shell'] = -1; run(**opts)` -- EVADES
- Dict union: `base | {'shell': -1}` -- EVADES
- Aug union: `opts |= {'shell': -1}` -- EVADES

**Confirmed evasion values:** `-1`, `-42`, `-999`, `-0.1`, `-1.0`, `(-1+0j)`, `(-1+2j)`

**Note:** `-0` and `-0.0` also get dropped (same root cause), but since they are falsy, the end result is accidentally correct. However, this means the detector is making the right decision for the wrong reason on those inputs.

### 2. Complex Expression Evasion via ast.BinOp (same root cause)

**Severity:** MEDIUM -- less likely to appear in real-world code

Complex numbers expressed as `(1+0j)` produce `ast.BinOp(Add)` in the AST, which is not `ast.Constant`. Same silent-drop behavior.

## Regression Test Candidates

5 specific inputs that should become permanent test cases (saved to `regression-candidates.txt`):

1. `subprocess.run(['ls'], **{'shell': -1})` -- negative int inline dict
2. `subprocess.run(['ls'], **{'shell': -1.0})` -- negative float inline dict
3. `subprocess.run(['ls'], **{'shell': (1+0j)})` -- complex with real part inline dict
4. `opts = {'shell': -1}; subprocess.run(['ls'], **opts)` -- negative int tracked dict
5. `subprocess.run(['ls'], **{'shell': -1})` via `analyze_python()` -- full pipeline

## Recommendations

Ordered by impact:

1. **[MUST-FIX] Handle ast.UnaryOp in _extract_dict_literal and _track_subscript_assign.**
   Add a helper function that evaluates simple constant expressions:
   ```python
   def _eval_constant(node: ast.expr) -> object | None:
       if isinstance(node, ast.Constant):
           return node.value
       if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
           if isinstance(node.operand, ast.Constant):
               return -node.operand.value
       if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
           # Handle (real+imagj) complex literals
           if isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
               if isinstance(node.right.value, complex):
                   return node.left.value + node.right.value
       return None
   ```
   Use this in `_extract_dict_literal` (line 263) and `_track_subscript_assign` (line 185) instead of bare `isinstance(value, ast.Constant)`.

2. **[SHOULD-FIX] Also handle ast.UnaryOp(UAdd) for completeness** (`+1` is valid Python and produces UnaryOp).

3. **[TRACK] Add regression tests** from `regression-candidates.txt` to the permanent test suite once the fix is in place.
