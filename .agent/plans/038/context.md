# Plan Context

Accumulated knowledge across sessions. Updated by /run at session end.

Entry format: `- [ISO-timestamp] (part-ref) content`

## Decisions

- [2026-03-22T00:00:00Z] (planning) Chose parallel ref_table (dict[str, RefEntry]) over extending symbol_table type — avoids breaking all existing consumers of dict[str, str]
- [2026-03-22T00:00:00Z] (planning) Depth-3 is the scope boundary — depth-4+ alias tracking deferred to future plan
- [2026-03-22T00:00:00Z] (planning) Eager resolution — m.system resolves to 'os.system' at assignment time, not lazily at call site
- [2026-03-22T00:00:00Z] (planning) Detection outcome is EXEC-002 (code execution) for resolved dangerous calls, not EXEC-006 (indirection)
- [2026-03-22T00:00:00Z] (planning) Part A fixes depth-1 gaps first (node-level, no infrastructure) — these are critical standalone fixes

## Learnings

- [2026-03-22T00:00:00Z] (planning) _ast_detectors.py at 311/350 lines — only 39 lines of headroom for Part A additions
- [2026-03-22T00:00:00Z] (planning) _ast_dynamic_exec_detector.py at 123/350 — ample room (227 lines) for Parts C+D
- [2026-03-22T00:00:00Z] (planning) get_call_name handles Name and single-level Attribute but not builtins.__import__ pattern
- [2026-03-22T00:00:00Z] (planning) _DANGEROUS_NAMES includes getattr and __import__ but these are indirection names, not execution — inline chain detector should use a subset excluding them
- [2026-03-22T00:00:00Z] (planning) _build_scope_map and _scoped_lookup are reusable for ref_table scope awareness
- [2026-03-22T00:00:00Z] (planning) No other AST-based scanner does depth-3 ref tracking on raw AST — this is novel; tools that do (Semgrep, CodeQL, Pysa) all use IR/CFG
- [2026-03-22T00:00:00Z] (planning) Real-world malware (2025-2026 PyPI): __import__('builtins').exec(__import__('base64').b64decode(...)) is the most common inline chain pattern

- [2026-03-22T01:00:00Z] (part-a) _ast_detectors.py is now at 348/350 lines — effectively frozen; any future addition requires extracting a helper to a sibling module
- [2026-03-22T01:00:00Z] (part-a) _detect_inline_import_chain added as node-level detector matching Call(func=Attribute(value=Call, attr=dangerous)); registered in _DETECTORS tuple
- [2026-03-22T01:00:00Z] (part-a) builtins.__import__ and __builtins__.__import__ added to _detect_dynamic_imports name check
- [2026-03-22T01:00:00Z] (part-a) ast.Constant.value can be bytes — str() guard needed for mypy str-bytes-safe check

- [2026-03-22T01:30:00Z] (part-b) _ast_ref_tracker.py created (103 lines) — RefEntry frozen dataclass + build_ref_table using _build_scope_map for scope awareness
- [2026-03-22T01:30:00Z] (part-b) build_ref_table recognizes __import__, importlib.import_module, builtins.__import__, __builtins__.__import__ via _IMPORT_CALL_NAMES frozenset
- [2026-03-22T01:30:00Z] (part-b) refine-and-confirm removed dead _ref_table assignment from analyze_python — ref_table must be re-wired when consumed in Part C
- [2026-03-22T01:30:00Z] (part-b) _build_scope_map without method_scope=True maps class body to ClassName scope — correct for ref_table

- [2026-03-22T02:00:00Z] (part-c) _ast_dynamic_exec_detector.py extended with ref_table-aware detection — _ref_lookup, _check_ref_call, _check_ref_attr_call, _track_func_ref helpers added
- [2026-03-22T02:00:00Z] (part-c) subprocess.call is in _SUBPROCESS_CALLS not _UNSAFE_EXEC_CALLS — combined both sets as _DANGEROUS_QUALIFIED for ref-table attr checking
- [2026-03-22T02:00:00Z] (part-c) _ast_dynamic_exec_detector.py now at 232/350 (98 lines headroom for Part D)
- [2026-03-22T02:00:00Z] (part-c) func_ref tracking mutates ref_table dict in-place — intentional for Part D bare call resolution

- [2026-03-22T02:30:00Z] (part-d) depth-3 helpers extracted to _ast_dynamic_exec_depth3.py — shared constants moved there, one-directional import chain (detector -> depth3)
- [2026-03-22T02:30:00Z] (part-d) ast.walk BFS order naturally ensures Assign (tracking) before sibling Call (detection) — no explicit ordering needed
- [2026-03-22T02:30:00Z] (group-verify) Parts C+D verified together — 8/8 criteria met, 3782 tests passing

## Blockers

<!-- None identified -->
