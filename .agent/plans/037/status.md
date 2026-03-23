# Plan Status

Human-readable progress summary. Updated by /run after each part completes.

## Parts

| Part | Title | Status |
|------|-------|--------|
| a | Tree-level dynamic exec detector (symbol table + taint sink) | Done |
| b | Scanner-level precision — dedup preference and end-to-end validation | Done |

## Key Findings

- (part-a) _SENSITIVE_MODULES and _resolve_first_arg live in _ast_dynamic_exec_detector.py (sole consumer)
- (part-a) _ast_detectors.py at 311/350 after refactor
- (part-b) _deduplicate() now prefers AST findings over regex — AST precision reaches scanner output
- (part-b) Complexity fix: detect_dynamic_exec extracted into 3 functions (main + 2 helpers)

## Current State

All parts complete. Ready for end-of-plan gates.
