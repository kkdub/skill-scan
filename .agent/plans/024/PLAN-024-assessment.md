 Codex Review — PLAN-024

  Critical Issues

  1. Coverage report internally wrong. parts.requirements never references R021, R022, or R-IMP009 — plan claims 38/38 covered
   but 3 requirements are unmapped.
  2. C-a1 grep is non-falsifiable. grep if isinstance.*elif isinstance already returns zero today because the current
  _try_resolve_split chain uses isinstance(node, ast.BinOp) style (not if isinstance...elif isinstance on a single line). The
  check passes before any work is done.
  3. Hard contradiction on finding flow. Plan says "no new finding emission paths — flow through existing _check_dangerous",
  but Part d explicitly adds a _DETECTORS detector that bypasses _check_dangerous (uses _make_finding directly via
  ast_analyzer.py).
  4. Part d signature mismatch. Plan describes _detect_decorator_evasion(tree, ...) (tree-level), but _DETECTORS are
  node-level callables (node, file_path, alias_map=...) invoked per AST node.
  5. Part d import cycle risk. Importing _NAME_RULE from _ast_split_detector into _ast_detectors creates a cycle —
  _ast_split_detector already imports from _ast_detectors.
  6. Part e tracked-variable comprehension is infeasible. Symbol table only tracks dict[str, str] — codes = [101,...] (integer
   list) is not tracked. Requirement R017 ("tracked-variable variant") likely needs symbol table changes, which are
  prohibited/out of scope.
  7. Acceptance criteria allow false green. "At least one EXEC-002/006 finding" can be satisfied by existing
  _detect_string_concat_evasion in _ast_helpers/_ast_detectors, not by the new resolver logic.
  8. R002 (≤200 lines) only enforced in Part a but Parts b/c/e also modify _ast_split_detector.py — final state can violate
  R002.

  Warnings

  9. build_alias_map audit claim overstated — nested imports are intentionally ignored.
  10. bash::wc -l verification is environment-fragile — repo runs in Windows/MSYS context.
  11. Plan omits explicit stop condition/completion gate (unlike PLAN-023).

  Questions

  12. Should decorator detection produce split-evasion-style matched text, or should corpus tests switch to rule_id filtering
  entirely?
  13. Is Part e tracked-variable support (codes = [101,...]; ''.join(chr(c) for c in codes)) actually required? If yes, the
  "no symbol table changes" constraint is incompatible.

  Verified Claims

  - PLAN-023 outputs present in codebase — dependency is reasonable
  - resolve_operand, resolve_binop_chain, resolve_expr exist in _ast_split_resolve.py
  - _resolve_generator_join exists in _ast_split_join_helpers.py (identity generators only)
  - Corpus filter is text-matching ("split"/"encoded") — won't naturally include decorator findings

  Assessment

  Not ready to execute. The single biggest risk is false green: several acceptance checks are weak or structurally broken, so
  parts can "pass" while the intended behaviors are still incorrect or incomplete.

  ---
