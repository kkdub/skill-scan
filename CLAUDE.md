# skill-scan

Security scanner for agent skills — detect prompt injection, malicious code, and data exfiltration before installation.

## Quick Reference

- **Plans & specs**: `.agent/plans/`
- **Code patterns and rules**: `.agent/standards/`
- **Workflow context**: `.agent/WORKFLOW.md`
- **Detailed module docs**: `.agent/ARCHITECTURE-REFERENCE.md`
- **Known debt**: `.agent/status/debt.yaml`

## Stack

Python 3.13, click, ruff, mypy, pytest, bandit

## Workflow

1. Read existing code before modifying
2. Make changes
3. Run `make check`

```bash
make install  # Install dependencies
make check    # All quality checks (run early, run often)
```

## Code

- Follow `.agent/standards/CODE-PATTERNS.md` for design decisions
- Follow `.agent/standards/TEST-PATTERNS.md` when writing or modifying tests
- Rules enforced via `.agent/standards/code-rules.json`
- Type hints on all public functions
- Tests in `tests/`
- Core scanner engine and decoder use stdlib only (`re`, `pathlib`, `json`, `tomllib`, `base64`, `binascii`, `ast`, `concurrent.futures`, `urllib.parse`)
- Don't add deps without `uv` + `pyproject.toml`
- **Max 350 lines per file** (source code in `src/` and `tests/`)

## Project Structure

```
src/skill_scan/
  ast_analyzer.py               # Facade: analyze_python()
  _ast_detectors.py             # Node-level detectors (_detect_*)
  _ast_imports.py                # build_alias_map + get_call_name
  _ast_string_resolver.py        # String-resolution pipeline
  _ast_rot13.py                  # ROT13 detection (codec, maketrans)
  _ast_rot13_branch_analysis.py  # ROT13 branch case analysis
  _ast_symbol_table.py           # Symbol table builder
  _ast_symbol_table_*.py         # Assignments, self.attr, returns, dict/list tracking
  _ast_split_detector.py         # Split-evasion detector
  _ast_split_*.py                # Resolution sub-modules (format, bytes, chr, reduce, etc.)
  _ast_terminal_body.py          # Terminal-body detection (shared helper)
  _ast_kwargs_detector.py        # Kwargs unpacking detector (facade)
  _ast_kwargs_dict_tracker.py    # Dict-collection pre-pass
  _ast_exfil_detector.py         # Subprocess list-arg + DNS exfil
  _ast_inline_chain_detector.py  # Inline import chain detector (_detect_inline_import_chain, _INLINE_CHAIN_ATTRS, _IMPORT_CALL_NAMES)
  _ast_dynamic_exec_detector.py  # Dynamic exec detector (depth 1-3)
  _ast_ref_tracker.py            # Ref-table pre-pass (RefEntry + build_ref_table)
  _ast_dynamic_exec_depth3.py    # Depth-3 detection helpers
  _ast_dunder_chain_detector.py  # MRO walk / dunder chain (EXEC-011)
  _ast_loop_unroller.py          # Static for-loop unrolling
  package_analyzer.py            # Facade: analyze_package()
  _package_risk_*.py             # Correlations, inventory, scoring policy
  _package_text.py               # Facade: TextSignal, classify_file_role()
  _package_text_*.py             # Patterns, roles, signals, signal utils
  _package_url_*.py              # URL extraction + classification
  decoder.py                     # Facade: EncodedPayload, extract/decode
  _decoder_*.py                  # Base64/hex, URL/unicode decode
  content_scanner.py             # File I/O + rule dispatch + concurrent scanning
  suppression.py                 # Inline noqa suppression
  rules/engine.py                # Rule matching engine
  rules/_multiline_pi.py         # Multiline PI scanning
  rules/_fewshot_pi.py           # Few-shot conversational attack detector (PI-030)
  rules/_context_heuristic.py    # Context suppression: suppresses PI-010+ inside code fences/comments
  rules/_agent_context_heuristic.py  # AGENT-category post-filter: 4-signal scoring (keyword-position, code-fence, heading-proximity, file-role)
  rules/_agent_compound_detector.py   # AGENT-006 sliding-window compound kill-chain detector
  rules/data/obfuscation.toml    # OBFS-001..005 (OBFS-001, EXEC-011 have patterns=[]; AST-only)
  rules/data/prompt_injection_jailbreak.toml  # PI-010..016 signatures, PI-020..022 fuzzy, PI-030 stub
  rules/data/agent_manipulation.toml          # AGENT-001 (file-write coercion; category=agent-manipulation)
tests/                           # Mirrors src/ structure; unit/ for unit tests
scripts/                         # Quality & analysis scripts
.agent/                          # Plans, standards, workflow
```

## Architecture Notes

For detailed module-level docs, see `.agent/ARCHITECTURE-REFERENCE.md`.

**Facade re-export pattern**: `ast_analyzer.py`, `decoder.py`, and `_package_text.py` re-export from private siblings. Import public names from the facade, not the `_` modules.

**Registration patterns** — where to add new things:
- `_DETECTORS` tuple in `ast_analyzer.py` — node-level detectors (one finding per node)
- `_RESOLVERS` tuple in `_ast_split_detector.py` — split-evasion string resolvers; each resolver must return `tuple[str, str] | None` (value, label)
- `_STRUCTURAL_PI_DETECTORS` tuple in `engine.py` — structural PI detectors (full-content, callback injection pattern); add new PI detectors here alongside `_multiline_pi_findings` and `_fewshot_pi_findings`
- `_STRUCTURAL_DETECTORS` tuple in `engine.py` — structural post-filter detectors invoked after PI structural detectors; callback signature: `(lines, file_path, findings) -> list[Finding]` (full typed form in invariants below); each detector handles its own category filtering; detectors that append new findings (e.g. `detect_compound_attack`) also belong in this tuple alongside post-filters
- Tree-level detectors needing full symbol table go in `analyze_python()` directly
- Table-driven configs (`_DANGEROUS_KWARGS`, `_CORRELATION_RULES`, `_SUBPROCESS_CALLS`, etc.) — extend by adding entries
- New jailbreak TOML rules: add to `rules/data/prompt_injection_jailbreak.toml`; signatures use `confidence='stable'`, fuzzy synonym-slot patterns use `confidence='fuzzy'`; code-only detectors use `patterns=[]` stub (PI-030 pattern)
- New `agent-manipulation` TOML rules: add to `rules/data/agent_manipulation.toml`; no `confidence` field needed (loader defaults to `stable`); field order: severity, category, description, recommendation, patterns, exclude_patterns, path_exclude_patterns

**Critical invariants** (violating these causes silent bugs):
- `_SHADOW` identity: always `existing is _SHADOW`, never `==` — because `_SHADOW == []` is True
- Bare `# noqa` does NOT suppress — security scanner requires explicit `# noqa: RULE-ID`
- `_deduplicate()` in `content_scanner.py` prefers AST findings over regex for same `(rule_id, line)` — do not revert
- `Finding()` directly for non-`malicious-code` categories — `_make_finding` hardcodes that category; ROT13 uses `obfuscation`, exfil uses `data-exfiltration`
- `ref_table` (`dict[str, RefEntry]`) is parallel to `symbol_table` (`dict[str, str]`) — never merged; same scope-key convention, different value types; method-scoped keys have the form `ClassName.method.var` (from `method_scope=True` in `_build_scope_map`)
- `build_ref_table` uses `_walk_body` (linear source-order walk), not `ast.walk` — source-order is required for last-assignment-wins rebinding; non-import `Call` assignments delete the existing ref_table entry for that scope key
- Deferred imports in `_ast_symbol_table.py` break circular deps — don't reorganize without checking
- `_process_nested` in `_ast_symbol_table.py`: recurses into inner bodies BEFORE routing nonlocal declarations — do NOT reorder
- `suppress_in_safe_context` in `_context_heuristic.py` only suppresses PI-010+ rules — PI-001..009 are intentionally unaffected (R-IMP001); normalized file-scope findings added after `_line_phase_findings` bypass this suppression (known debt)
- Structural PI detector callback signature: `(lines, file_path, pi_rules, existing, make_finding, is_excluded) -> list[Finding]` — all detectors in `_STRUCTURAL_PI_DETECTORS` must use this exact signature
- `_RESOLVERS` resolver contract: registry-facing resolvers return `tuple[str, str] | None` (value, label); internal helpers (`resolve_expr`, `resolve_operand`, `resolve_call_return`, `resolve_fromhex_concat`) keep `str | None`; label is `"call-return"` if any leaf resolved via `resolve_call_return`, `"split variable"` otherwise — `_label_from_call_return` in `_ast_split_resolve.py` is the predicate for this check
- Dispatch order in `_line_phase_findings`: PI structural detectors (`_STRUCTURAL_PI_DETECTORS`) run first, then general structural post-filters (`_STRUCTURAL_DETECTORS`), then PI context suppression (`suppress_in_safe_context`) — do NOT reorder
- `_STRUCTURAL_DETECTORS` callback signature: `(lines: list[str], file_path: str, findings: list[Finding]) -> list[Finding]` — all detectors in `_STRUCTURAL_DETECTORS` must use this exact signature; category filtering is internal to each detector

## Code Indexing

codebase-memory-mcp is available for structural code queries — use it for call-graph tracing,
function/class search, and architecture overview. Especially useful in this repo due to the
30+ tightly coupled private modules. Use `trace_call_path` before modifying any detector to
understand the full caller/callee chain through the facade layers.

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
