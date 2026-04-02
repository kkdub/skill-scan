- [issue]: `R-IMP001` is currently unverifiable as written. The requirement points to `tests/unit/test_dynamic_exec.py`, which does not exist, so the plan can claim completion without a real check for that requirement. Evidence: [requirements.yaml](/home/kkdub/skill-scan/.agent/plans/040/requirements.yaml), missing file path in repo.

- [issue]: `R001` verification target is inconsistent with the implementation plan. `requirements.yaml` says verify via `tests/unit/test_ast_detectors.py`, but Part A adds subprocess inline-chain tests in `tests/unit/test_inline_import_chain.py`; `test_ast_detectors.py` currently does not cover inline-chain subprocess attrs. Evidence: [requirements.yaml](/home/kkdub/skill-scan/.agent/plans/040/requirements.yaml), [test_ast_detectors.py](/home/kkdub/skill-scan/tests/unit/test_ast_detectors.py), [test_inline_import_chain.py](/home/kkdub/skill-scan/tests/unit/test_inline_import_chain.py).

- [issue]: Acceptance scenarios are not executable as written. They call `analyze_python(ast.parse(...), '<test>')`, but `analyze_python` expects `content: str`, not an AST object. This weakens acceptance validation quality. Evidence: [plan.yaml](/home/kkdub/skill-scan/.agent/plans/040/plan.yaml), [ast_analyzer.py](/home/kkdub/skill-scan/src/skill_scan/ast_analyzer.py).

- [issue]: Utilities audit contains a false claim: it says `ast_analyzer.py` re-exports `_INLINE_CHAIN_ATTRS` and `_IMPORT_CALL_NAMES`; it does not. That matters because risk mitigation depends on facade re-export correctness. Evidence: [plan.yaml utilities_audit](/home/kkdub/skill-scan/.agent/plans/040/plan.yaml), [ast_analyzer.py](/home/kkdub/skill-scan/src/skill_scan/ast_analyzer.py).

- [issue]: There is a direct contradiction inside the plan constraints: design constraints prohibit “reordering ast.walk BFS traversal” for ref_table population, while Part B/D6 explicitly replaces `ast.walk` with linear ordered traversal in `build_ref_table`. This can cause implementation hesitation or policy conflicts during execution. Evidence: [design-constraints.yaml](/home/kkdub/skill-scan/.agent/plans/040/design-constraints.yaml), [plan.yaml Part B](/home/kkdub/skill-scan/.agent/plans/040/plan.yaml).

- [issue]: Part dependency graph is overly sequential. Part B (method scope + rebinding in ref tracker/dynamic detector) is largely independent of Part A (inline-chain extraction) and could run in parallel; current `depends_on: [a]` adds avoidable critical-path time.

- [question]: Should `.agent/plans/040/requirements.yaml` be included in `allowed_files`? Without that, known broken verify pointers (`test_dynamic_exec.py`, `test_ast_detectors.py` mismatch) cannot be corrected as part of plan execution.

- [question]: Is “inline subprocess chains with obfuscated module names” intended to be a required capability or just a red-team probe? Current inline-chain detector logic is attr/import-call-name-centric, and the plan does not define concrete obfuscation acceptance cases.

- [assumption]: [verified] — `_build_scope_map(..., method_scope=True)` already exists and is used successfully elsewhere (`_ast_kwargs_detector`), so using it in ref tracking/dynamic exec is technically consistent. Evidence: [_ast_split_detector.py](/home/kkdub/skill-scan/src/skill_scan/_ast_split_detector.py), [_ast_kwargs_detector.py](/home/kkdub/skill-scan/src/skill_scan/_ast_kwargs_detector.py).

- [assumption]: [verified] — Forbidden files are realistically not required for the planned code changes (`_ast_split_detector.py`, `_ast_exfil_detector.py`, `_ast_symbol_table*.py` can remain untouched).

- [assumption]: [unverified] — The proposed linear recursive walk in `build_ref_table` will preserve all current edge-case coverage without regressions in nested control flow; the plan states it will recurse, but gives no concrete acceptance tests for branch-heavy assignment order beyond simple rebinding.

- [claim from plan]: [confirmed by reading /home/kkdub/skill-scan/src/skill_scan/_ast_detectors.py] `_ast_detectors.py` is at the line-budget edge (349 lines), so extraction is justified.

- [claim from plan]: [confirmed by reading /home/kkdub/skill-scan/src/skill_scan/_ast_dynamic_exec_depth3.py] `_ast_dynamic_exec_depth3.py` currently imports `_INLINE_CHAIN_ATTRS` from `_ast_detectors`, so coupling exists and must be addressed before expanding inline attrs.

- [claim from plan]: [confirmed by reading /home/kkdub/skill-scan/src/skill_scan/_ast_ref_tracker.py] `build_ref_table` currently uses `_build_scope_map(tree)` with default `method_scope=False` and `ast.walk`, so cross-method key collision/rebinding-staleness risk is real.

- [claim from plan]: [confirmed by reading /home/kkdub/skill-scan/.agent/status/improvements.yaml] The three PLAN-038 improvement entries targeted by PLAN-040 are present and unresolved, so Part D’s status-update work is grounded.

This plan is not ready to execute yet because the verification layer is internally inconsistent (broken test paths + non-executable acceptance snippets), which makes “done” status easy to claim without proving the core behavior changes. The single biggest risk is Part B integration: changing ref-table traversal semantics without strong branch/order acceptance tests can silently shift dynamic-exec detection behavior even if most existing tests still pass.

## Verification Summary
Date: 2026-04-02
Plan: plan.yaml (PLAN-040)
Reviewer model: gpt-5.3-codex

| # | Finding | Verdict | Action |
|---|---------|---------|--------|
| 1 | R-IMP001 verify points to nonexistent test file | valid | fixed: updated to test_dynamic_exec_detector.py |
| 2 | R001 verify target inconsistent with implementation | valid | fixed: updated to test_inline_import_chain.py |
| 3 | Acceptance scenarios pass ast.parse() not str | valid | fixed: changed to raw string content |
| 4 | Utilities audit falsely claims facade re-exports exist | valid | fixed: reworded to note re-exports must be added |
| 5 | Design constraints contradict Part B/D6 on ast.walk | valid | fixed: reworded prohibition to focus on ordering |
| 6 | Part B could parallelize with Part A | invalid | skipped: overlapping file edits make sequential practical |
| 7 | requirements.yaml not in allowed_files | valid | user decided: added to allowed_files |
| 8 | Obfuscated module names scenario undefined | valid | user decided: removed from Part C criteria/approach |
| 9 | _build_scope_map method_scope=True exists | verified | no action needed |
| 10 | Forbidden files not needed for changes | verified | no action needed |
| 11 | Linear walk preserves coverage (unverified) | acknowledged | no action: already in known_limitations |
| 12 | _ast_detectors.py at line-budget edge | confirmed | no action needed |
| 13 | _ast_dynamic_exec_depth3.py imports from _ast_detectors | confirmed | no action needed |
| 14 | build_ref_table uses method_scope=False and ast.walk | confirmed | no action needed |
| 15 | PLAN-038 improvement entries present and unresolved | confirmed | no action needed |
