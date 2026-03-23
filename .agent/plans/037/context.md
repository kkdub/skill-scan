# PLAN-037 Research Context

## Problem Statement

Attackers bypass static analysis by avoiding direct calls like `os.system()` and instead
use `__import__()` or `getattr()` with dynamically constructed strings to resolve and
execute malicious functions at runtime.

## Current Detection Inventory

### What's Already Detected

| Pattern | Rule ID | Severity | Detector | Level |
|---------|---------|----------|----------|-------|
| `__import__('os')` (constant arg) | EXEC-006 | HIGH | `_detect_dynamic_imports` | AST node |
| `importlib.import_module('os')` | EXEC-006 | HIGH | `_detect_dynamic_imports` | AST node |
| `getattr(x, 'ev'+'al')` (concat arg) | EXEC-006 | HIGH | `_detect_dynamic_access` | AST node |
| `getattr(x, chr(115)+chr(121))` (chr arg) | EXEC-006 | HIGH | `_detect_dynamic_access` | AST node |
| `getattr(os, 'system')` (literal constant) | EXEC-006 | HIGH | `_detect_dynamic_access` | AST node |
| `globals()['eval']` | EXEC-002 | CRITICAL | `_check_dynamic_dispatch` | AST node |
| `locals()['__import__']` | EXEC-006 | HIGH | `_check_dynamic_dispatch` | AST node |
| `globals()['__builtins__']['eval']` | EXEC-002 | CRITICAL | `_check_dynamic_dispatch` (two-level) | AST node |
| `obj.__dict__['system']` | EXEC-002 | CRITICAL | `_check_dynamic_dispatch` | AST node |
| `'ev' + 'al'` (string concat) | EXEC-002 | CRITICAL | `_detect_string_concat_evasion` | AST node |
| `@eval` / `@__import__` (decorator) | EXEC-002/006 | CRIT/HIGH | `_detect_decorator_evasion` | AST node |
| Regex `getattr\s*\(` | EXEC-006 | HIGH | malicious_code.toml | regex |
| Regex `__import__\s*\(` | EXEC-006 | HIGH | malicious_code.toml | regex |
| Regex `importlib\.import_module\s*\(` | EXEC-006 | HIGH | malicious_code.toml | regex |

### Corrected Understanding (Codex review 2026-03-22)

Previous context claimed `try_resolve_string()` returns `None` for plain `ast.Constant`.
This was **false**. `_ast_string_resolver.py:28` returns string constants directly:
```python
if isinstance(node, ast.Constant) and isinstance(node.value, str):
    return node.value
```
Therefore `getattr(os, 'system')` is already detected by `_detect_dynamic_access` via
`try_resolve_string` returning `'system'` which matches `_DANGEROUS_NAMES`.

Similarly, `_detect_dynamic_imports` fires on call name (`__import__`, `importlib.import_module`)
regardless of argument type. Both `__import__('os')` and `__import__(var)` trigger EXEC-006.

### Scanner-Level Reality (end-to-end testing 2026-03-22)

At the scanner level, **regex catches ALL getattr/import patterns** — including benign ones:

| Pattern | Scanner Detection | Source | Problem |
|---------|-------------------|--------|---------|
| `getattr(os, 'system')` | EXEC-006 HIGH | regex (AST masked by dedup) | Correct but AST message lost |
| `getattr(os, var='system')` | EXEC-006 HIGH | regex | Regex can't resolve var |
| `getattr(os, unknown)` | EXEC-006 HIGH | regex | Should be MEDIUM (uncertain) |
| `getattr(os, 'path')` | EXEC-006 HIGH | regex | **False positive** |
| `getattr(config, 'debug')` | EXEC-006 HIGH | regex | **False positive** |
| `getattr(self, 'process')` | EXEC-006 HIGH | regex | **False positive** |
| `__import__('json')` | EXEC-006 HIGH | regex + AST | **False positive** |
| `getattr(obj, 'name', default)` | EXEC-006 HIGH | regex | **False positive** |

AST detectors produce more precise results (only flag _DANGEROUS_NAMES) but the
`_deduplicate()` function in `content_scanner.py` prefers regex findings, masking AST.

### Actual Gaps

1. **`getattr(os, var)` where `var = 'system'` — symbol table resolution**
   Node-level `_detect_dynamic_access` can't access `symbol_table`. The variable arg
   is not resolved. Regex catches the call but without knowing the resolved value.

2. **`getattr(os, computed)` — taint sink on sensitive module**
   When the attr name can't be statically resolved AND the object is a sensitive module,
   the call is inherently suspicious but the severity should be MEDIUM (uncertain), not
   HIGH (confirmed dangerous). Currently everything is HIGH via regex.

3. **AST precision masked by dedup**
   `_deduplicate()` seeds `seen` from regex findings by `(rule_id, line)`, then drops AST
   findings with matching keys. Since EXEC-006 regex patterns match ALL getattr/import
   calls, AST findings are always masked. More precise AST severity/messages never reach
   scanner output.

### Out-of-Scope Gaps (too complex for this plan)

- **Module return value tracking**: `m = __import__('os'); m.system('ls')` — requires
  extending symbol table to track non-string values (module objects)
- **Function reference tracking**: `f = getattr(os, 'system'); f('cmd')` — same issue
- **Class-method local variable resolution**: `_process_class` in `_ast_symbol_table.py`
  does not export method-local variables to the result dict. Symbol-table lookups for
  variables defined inside class methods will not resolve. This is a pre-existing
  limitation of the symbol table and is out of scope.
- **Regex false positive reduction**: Narrowing the EXEC-006 TOML regex patterns to be
  more precise would reduce false positives but risks missing edge cases. Separate concern.

## Design Decisions

### Detection Strategy

Two-part approach:

1. **New tree-level detector** (needs symbol table):
   - `getattr` 2nd arg resolution via symbol table → EXEC-006 HIGH with resolved name
   - `getattr` taint sink: sensitive module + non-resolvable arg → EXEC-006 MEDIUM
   - NOT: `__import__`/`importlib.import_module` detection (already handled by existing
     node-level detector; no improvement possible without module-value tracking)

2. **Dedup preference change** (scanner-level integration):
   - Change `_deduplicate()` to prefer AST findings over regex when both produce same
     `(rule_id, line)` — AST findings carry more precise severity and matched_text
   - When AST produces no finding for a line, regex finding still stands as safety net

### Sensitive Modules

```python
_SENSITIVE_MODULES = frozenset({
    "os", "sys", "subprocess", "shutil", "socket",
    "builtins", "__builtins__", "importlib",
    "ctypes", "code", "codeop",
})
```

### Severity Tiers

| Detection | Severity | Rationale |
|-----------|----------|-----------|
| getattr(any, var->dangerous_name) via symbol table | HIGH | Confirmed dangerous function access |
| getattr(sensitive_module, non_resolvable) | MEDIUM | Suspicious but uncertain |

### False Positive Considerations

- `getattr(obj, 'name')` — non-dangerous attr: no AST finding (regex still fires)
- `getattr(config, unknown)` — non-sensitive module: no taint finding
- `hasattr(os, 'system')` — NOT getattr, should not trigger
- `__import__('json')` — benign but still flagged by existing detector (out of scope)

## Execution Log

### Part A (2026-03-22) — DONE
- Created `_ast_dynamic_exec_detector.py` (104 lines) with `detect_dynamic_exec()` tree-level detector
- Added `_SENSITIVE_MODULES` and `_resolve_first_arg` to the detector module (refactorer moved them from `_ast_detectors.py`)
- Wired into `analyze_python()` after `detect_kwargs_unpacking`
- 10 tests in `test_dynamic_exec_detector.py`, all pass
- `_ast_detectors.py` back to 311 lines after refactor (was 324 before move)
- Refactorer replaced direct `Finding()` construction with `_make_finding()` pattern
- DEBT: `_ast_split_comprehension` import ordering in `ast_analyzer.py` is pre-existing (not introduced here)
- Discovery: getattr with variable 2nd arg produced zero findings before this detector (no regex rule catches `getattr(os, var)` when var is a Name node — regex only matches the call syntax)

### Part B (2026-03-22) — DONE
- Changed `_deduplicate()` in `content_scanner.py` to prefer AST findings over regex when both exist for same (rule_id, line)
- 15 tests in `test_dynamic_exec_scanner.py`: dedup unit tests (5), scanner e2e (5), acceptance scenarios (5)
- Updated 2 existing tests in `test_ast_integration.py` that asserted old regex-priority behavior
- Refactorer extracted `_check_resolved_name` and `_check_taint_sink` helpers from `detect_dynamic_exec` to fix complexity violation (67→41 lines, complexity 11→10)
- `content_scanner.py` at 246/350 lines
- All 5 acceptance scenarios passing
