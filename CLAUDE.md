# skill-scan

Security scanner for agent skills — detect prompt injection, malicious code, and data exfiltration before installation.

## Quick Reference

- **Plans & specs**: `.agent/plans/`
- **Code patterns and rules**: `.agent/standards/`
- **Workflow context**: `.agent/WORKFLOW.md`
- **Detailed module docs**: `.agent/ARCHITECTURE-REFERENCE.md`

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
src/skill_scan/           # Production source code
  ast_analyzer.py         # Facade: analyze_python() entry point
  _ast_detectors.py       # Node-level detector functions (_detect_*)
  _ast_imports.py         # build_alias_map + get_call_name + _STAR_IMPORT_EXPANSIONS + _try_bodies
  _ast_string_resolver.py # String-resolution pipeline (resolve_string + join-resolution helpers)
  _ast_rot13.py           # ROT13 AST detectors (codec, maketrans)
  _ast_rot13_branch_analysis.py # ROT13 branch case analysis (extracted from _ast_rot13.py)
  _ast_symbol_table.py    # Symbol table builder (build_symbol_table)
  _ast_symbol_table_assignments.py   # Assignment-tracking helpers
  _ast_symbol_table_self_attrs.py    # Class-attribute helpers (self.attr tracking)
  _ast_symbol_table_returns.py       # Return-value extraction
  _ast_symbol_table_dict_tracker.py  # Dict/list literal helpers + dict.pop tracking + replace-chain resolution
  _ast_split_detector.py  # Split-evasion detector (detect_split_evasion)
  _ast_split_format.py    # Format/%-format resolution helpers
  _ast_split_format_map.py # format_map resolver (extracted from _ast_split_resolve.py)
  _ast_split_resolve.py   # Expression resolution helpers; re-exports from _ast_split_method_chains
  _ast_split_method_chains.py # Replace-chain and case-method-chain resolvers (extracted from _ast_split_resolve.py)
  _ast_split_match.py     # Dangerous-name matching + encoded-payload bridge for split-evasion results
  _ast_split_bytes.py     # Bytes-constructor resolution
  _ast_split_chr.py       # chr/ord/int resolution
  _ast_split_reduce.py    # reduce/operator concat resolution
  _ast_split_comprehension.py # Generator/comprehension join resolution; _collect_int_list_assigns pre-pass; delegates body walking to _walk_fn_body and nested function traversal to _collect_fn_body
  _ast_terminal_body.py          # Terminal-body detection (_is_terminal_body, _is_exhaustive_match); shared by int-list tracker and returns module
  _ast_split_int_list_tracker.py # Int-list mutation tracking (_SHADOW sentinel, _Decls type alias, _resolve_scope_key, _collect_fn_body, _walk_fn_body, _handle_int_list_stmt, _handle_assign, _handle_extend_call, _extend_tracked, _values_agree, _merge_branches)
  _ast_split_map_resolver.py # map(chr/str/lambda, [...]) resolution for join patterns
  _ast_split_star_unpack.py  # Star-unpack flattening for join arguments (_flatten_starred_list, _expand_starred, _maybe_flatten_starred)
  _ast_kwargs_detector.py # Kwargs unpacking detector (detect_kwargs_unpacking); re-exports from _ast_kwargs_dict_tracker.py
  _ast_kwargs_dict_tracker.py # Dict-collection pre-pass + .update() tracking; _build_string_table for dynamic key resolution
  _ast_exfil_detector.py  # Subprocess list-arg + DNS exfil detectors (_detect_subprocess_list_exfil, _detect_dns_exfil)
  _ast_dynamic_exec_detector.py # Tree-level dynamic exec detector (detect_dynamic_exec); symbol-table resolution + taint-sink (EXEC-006) + ref_table depth-2/3 detection (EXEC-002); imports helpers from _ast_dynamic_exec_depth3.py
  _ast_ref_tracker.py     # Ref-table pre-pass: RefEntry frozen dataclass + build_ref_table(); tracks __import__/importlib.import_module return values as module refs
  _ast_dynamic_exec_depth3.py # Depth-3 detection helpers: _track_getattr_ref, _check_bare_func_call; shared constants _EXEC_ATTR_NAMES, _DANGEROUS_QUALIFIED; _ref_lookup, _is_dangerous_ref_attr
  _ast_dunder_chain_detector.py # MRO walk / dunder chain detector (_detect_dunder_chain); EXEC-011; uses _dunder_inner marker for dedup; registered in _DETECTORS
  _ast_loop_unroller.py   # Static for-loop unrolling pre-pass (collect_loop_assigns)
  package_analyzer.py     # Facade: analyze_package() entry point
  _package_risk_correlations.py # Cross-file correlation rules (table-driven); apply_correlations, correlation_bonus, has_multi_role_medium_risk
  _package_risk_inventory.py    # File I/O collection; build_role_map, count_roles, analyze_text_files
  _package_risk_policy.py       # Scoring policy tables (ROLE_WEIGHT, SEVERITY_POINTS, CATEGORY_DRIVER); weighted_points, final_band, top_drivers
  _package_text.py        # Facade: TextSignal model, classify_file_role(), analyze_text_content()
  _package_text_patterns.py     # Compiled regex patterns for text signal detection
  _package_text_roles.py        # File-role classification + snippet extraction (classify_file_role, extract_command_snippets, has_command)
  _package_text_signal_utils.py # Signal utility helpers (is_warning_like_reference, deduplicate_signals)
  _package_text_signals.py      # TextSignal dataclass + build_text_signals(); operator/secret/remote/URL signal builders
  _package_url_analysis.py      # URL extraction + classify_url_signal(); extract_urls_with_context, has_execution_context
  _package_url_patterns.py      # Marker tables and regex patterns for URL analysis
  decoder.py              # Facade: EncodedPayload, extract/decode
  _decoder_base64_hex.py  # Base64/hex extraction and decode
  _decoder_url_unicode.py # URL/unicode-escape extraction and decode
  content_scanner.py      # File I/O + rule dispatch + concurrent scanning
  suppression.py          # Inline noqa suppression
  rules/
    engine.py             # Rule matching engine
    _multiline_pi.py      # Multiline PI scanning (extracted from engine.py)
    data/
      obfuscation.toml    # OBFS-001..005 (OBFS-001 has empty patterns=[]; detection is AST-only)
tests/
  unit/
    test_ast_split_case_methods.py      # Case-method resolver tests
    test_ast_split_int_list_tracker.py  # Int-list concat, extend-var, class-body pre-pass tests (PLAN-032 Part A); global/nonlocal int-list scope tests (PLAN-034); updated for branch-aware shadow behavior (PLAN-035)
    test_int_list_branch_merge.py       # Branch-aware if/else and match/case merge tests for int-list pre-pass (PLAN-035, 28 tests); terminal branch exclusion integration tests (PLAN-036)
    test_terminal_body.py               # Unit tests for _is_terminal_body helper (PLAN-036 Part A)
    test_terminal_branch_exclusion.py   # Unit-level tests for terminal branch exclusion wired into _walk_fn_body (PLAN-036 Part B)
    test_ast_kwargs_dict_tracker.py     # Dynamic key resolution tests (PLAN-032 Part B)
    test_ast_split_star_unpack.py       # Star-unpack flattening tests (PLAN-032 Part C)
    test_part_d_classvar_dictpop.py     # Class-body scope, classvar assembly, dict.pop tests (PLAN-032 Part D)
    test_hex_escape_resolution.py       # Hex escape .replace() chain + fromhex(var) tests (PLAN-032 Part E)
    test_package_analyzer.py            # Package-level risk analysis tests (classify_file_role, analyze_text_content, end-to-end scan)
    test_dynamic_exec_detector.py       # detect_dynamic_exec unit tests — symbol-table resolution + taint-sink (PLAN-037, 10 tests)
    test_dynamic_exec_scanner.py        # Scanner-level e2e tests for AST-over-regex dedup preference (PLAN-037, 15 tests)
    test_inline_import_chain.py         # _detect_inline_import_chain tests (PLAN-038 Part A, 16 tests)
    test_ref_tracker.py                 # build_ref_table unit tests — scope-aware keys, module ref extraction (PLAN-038 Part B, 21 tests)
    test_depth2_ref_detection.py        # Depth-2 ref_table detection tests — m.system() on tracked refs (PLAN-038 Part C, 16 tests)
    test_depth3_ref_detection.py        # Depth-3 detection tests — getattr on tracked ref + bare call resolution; 4 acceptance scenarios (PLAN-038 Part D, 20 tests)
    test_dunder_chain_detector.py       # EXEC-011 dunder chain detector tests — canonical MRO walk, execution escape, benign single/multi-dunder, edge cases, scanner e2e (PLAN-039, 23 tests)
    ...                                 # Other tests mirror src/ structure
scripts/                  # Quality & analysis scripts
.agent/                   # Plans, standards, workflow
```

## Architecture Notes

Key patterns and invariants. For detailed module-level docs, see `.agent/ARCHITECTURE-REFERENCE.md`.

**Facade Re-export Pattern**: `ast_analyzer.py`, `decoder.py`, and `_package_text.py` are facade modules — they re-export from private siblings. Import public names from the facade, not the `_` modules.

**Registration patterns** — follow these when adding new detectors:
- `_DETECTORS` tuple in `ast_analyzer.py` — node-level detectors (one finding per node)
- `_RESOLVERS` tuple in `_ast_split_detector.py` — string resolvers for split-evasion; signature: `(node, symbol_table, scope, *, alias_map=None) -> str | None`
- Tree-level detectors needing the full symbol table (`detect_split_evasion`, `detect_kwargs_unpacking`, `detect_dynamic_exec`) go in `analyze_python()` directly, not in `_DETECTORS`; `_detect_custom_rot13` is walked separately over `ast.FunctionDef | ast.AsyncFunctionDef` nodes (requires full function body, not per-node dispatch)
- `_NAME_RULE` / `_DECORATOR_RULE` — lookup tables mapping dangerous names to `(rule_id, severity, prefix)`; use when one detector emits different rule IDs per name
- `_DANGEROUS_KWARGS` — table-driven config for kwargs detector; extend by adding entries, no code changes needed
- `_collect_int_list_assigns(tree)` in `_ast_split_comprehension.py` — parallel pre-pass collecting `Name = [int, ...]` assignments AND tracking `+=`/`.extend()` mutations; built in `analyze_python()` and threaded to `detect_split_evasion` via `int_list_table` kwarg; mutation helpers live in `_ast_split_int_list_tracker.py`; also walks ClassDef body directly (class-level int-lists tracked under `ClassName.varname` key); delegates body walking to `_walk_fn_body` and nested function traversal to `_collect_fn_body` (handles global/nonlocal declarations)
- `_resolve_scope_key(name, scope, declarations, enclosing_scope)` in `_ast_split_int_list_tracker.py` — central scope-key builder for global/nonlocal declaration resolution in int-list tracking; `global name` resolves to bare name (module-level key); `nonlocal name` resolves to `enclosing_scope.name`; otherwise uses `scope.name` (existing behaviour); declarations parameter is `_Decls = tuple[set[str], set[str]] | None`
- `_walk_fn_body(body, scope, result, decls=None, enclosing="")` in `_ast_split_int_list_tracker.py` — branch-aware body walker for int-list pre-pass; `ast.If` and `ast.Match` nodes use snapshot-walk-merge so mutually exclusive branches do not contaminate each other; terminal branches (those where `_is_terminal_body` returns True) are excluded from the merge — they can never reach post-branch code; `For`/`While`/`Try`/`With` sub-bodies are still walked sequentially; calls `_merge_branches` to reconcile branch snapshots; non-exhaustive match adds the pre-match snapshot as an extra branch (models "no case matched"); `_sub_bodies` and `_is_terminal_body`/`_is_exhaustive_match` imports are deferred inside this function to break circular deps
- `_collect_fn_body(fn, scope, enclosing, result)` in `_ast_split_int_list_tracker.py` — recursive nested function traversal with declaration awareness for int-list pre-pass; calls `_collect_scope_declarations` to gather global/nonlocal sets for the function body, delegates body walk to `_walk_fn_body` with declarations active, then recurses into nested `FunctionDef`/`AsyncFunctionDef` nodes; pass-through nonlocal chain determined per nested function by checking whether parent owns any of child's nonlocal names via result dict lookup (`scope.name` key existence); transparent intermediates (no local binding) pass through to enclosing
- `_values_agree(vals: list[list[int]]) -> bool` in `_ast_split_int_list_tracker.py` — checks whether all values in a list of branch results agree; identity comparison for `_SHADOW` (`is`), value equality for concrete lists; used by `_merge_branches` per-key decision
- `_merge_branches(branches, result)` in `_ast_split_int_list_tracker.py` — N-way conservative merge of branch results into `result`; keys present in all branches with identical values are kept; keys with differing values across any branches are replaced with `_SHADOW`; keys present in only some branches are kept (security-conservative — keeps any potentially real int-list); must use identity (`is`) not equality (`==`) for `_SHADOW` comparisons since `_SHADOW == []` is True
- `_is_terminal_body(body: list[ast.stmt]) -> bool` in `_ast_terminal_body.py` — returns True if every code path through `body` exits scope via `return` or `raise`; conservative (returns False for unrecognized nodes, loops, bare `if` without `else`); handles nested `if/else`, `try/except/finally`, `with`, and `match`; `break`/`continue` are NOT terminal (they exit loop iteration only); used by `_walk_fn_body` to exclude terminal branches from the int-list merge
- `_is_exhaustive_match(node: ast.Match) -> bool` in `_ast_terminal_body.py` — returns True if the match has an unguarded wildcard case (last case pattern is `MatchAs` with `name=None` and `case.guard is None`); used by `_walk_fn_body` to decide whether to include the pre-match snapshot as an extra branch in the N-way merge; also used by `_match_is_terminal` in the same module; moved from `_ast_split_int_list_tracker.py` in PLAN-036
- `_handle_string_list_literal` in `_ast_symbol_table_dict_tracker.py` — tracks `name = ['ev', 'al']` assignments as indexed elements `name[0]`, `name[1]`, etc. and `name.__len__` in the symbol table; enables `parts[0] + parts[1]` BinOp resolution and star-unpack flattening
- `_handle_dict_literal` in `_ast_symbol_table_dict_tracker.py` — tracks `name = {'key': 'val'}` assignments as composite keys `name[key]` in the symbol table; enables dict.pop() resolution
- `_handle_dict_pop` in `_ast_symbol_table_dict_tracker.py` — resolves `target = d.pop('key')` by looking up `d[key]` in the symbol table composite key entries; called first in `_process_stmt` before `_handle_assign`
- `_resolve_replace_chain_simple` in `_ast_symbol_table_dict_tracker.py` — resolves chained `.replace(old, new)` on a constant or tracked variable in the symbol table builder; used to track hex strings with escape-sequence separators
- `_maybe_flatten_starred` in `_ast_split_star_unpack.py` — expands `ast.Starred` elements in join argument lists by looking up `name.__len__` and `name[i]` entries in the symbol table; called from `_resolve_join_call` before `_resolve_join_elements`
- `_build_string_table(body)` in `_ast_kwargs_dict_tracker.py` — local pre-pass that tracks `name = 'literal'` and `name = 'a' + 'b'` string assignments within a body; passed to `_extract_dict_literal` for Name key resolution in kwargs dict tracking
- `_CASE_METHODS` frozenset + `_is_case_method` / `_resolve_case_method_chain` in `_ast_split_method_chains.py` — resolves `.lower()`, `.upper()`, `.title()`, `.swapcase()`, `.capitalize()`, `.casefold()` chains; registered in `_RESOLVERS` before `_is_call` (follows `_is_replace_call` / `_resolve_replace_chain` pattern)
- `MRO_WALK_DUNDERS` / `EXEC_ESCAPE_DUNDERS` in `_ast_dunder_chain_detector.py` — two frozensets defining the two tiers of dangerous dunders; `MRO_WALK_DUNDERS` = `{__class__, __base__, __bases__, __mro__, __subclasses__}`; `EXEC_ESCAPE_DUNDERS` = `{__globals__, __builtins__, __import__, __getattr__, __code__}`; extend by adding entries to the appropriate set — severity logic (`CRITICAL` vs `HIGH`) is derived automatically
- `_detect_dunder_chain` in `_ast_dunder_chain_detector.py` — node-level detector registered in `_DETECTORS`; emits EXEC-011; uses `_collect_chain` to walk inward from an `ast.Attribute` node, collecting consecutive dangerous dunders; non-dangerous dunders (e.g., `__init__`, `__new__`) are transparent bridges; `ast.Subscript` and `ast.Call` nodes are also transparent (skipped through); non-dunder attribute names break the chain; chains of 2+ dangerous dunders emit a finding; inner `ast.Attribute` nodes in the chain are marked with `_dunder_inner = True` to prevent duplicate findings when `ast.walk` visits them later
- `_SUBPROCESS_CALLS` / `_NETWORK_TOOLS` in `_ast_exfil_detector.py` — frozensets defining which subprocess variants and tool names trigger EXFIL-008; extend by adding entries, no code changes needed
- `_DNS_EXFIL_TARGETS` in `_ast_exfil_detector.py` — frozenset defining which calls trigger EXFIL-006 DNS exfil detection (`socket.getaddrinfo`); non-literal first arg triggers finding; extend by adding entries
- `_STAR_IMPORT_EXPANSIONS` dict in `_ast_imports.py` — allowlist mapping dangerous modules to their dangerous exports; `from os import *` expands to `os.system`, `os.popen`, etc. in `alias_map`; extend by adding module entries
- `collect_loop_assigns(tree)` in `_ast_loop_unroller.py` — pre-pass that resolves `for c in ['e','v','a','l']: name += c` patterns; called in `analyze_python()` and merged into `symbol_table` before `detect_split_evasion` runs; supports inline list literals and local list-literal name references; single-level loops with one AugAssign body only
- `_handle_update_call` in `_ast_kwargs_dict_tracker.py` — handles `dict.update({...})` in the kwargs pre-pass; follows same pattern as `_track_aug_union`
- `_try_bodies(node)` in `_ast_imports.py` — returns all body lists from a `Try` node (body, handlers, orelse, finalbody); used by `_collect_imports` to recurse into `try/except` blocks
- `detect_dynamic_exec(tree, file_path, alias_map, symbol_table, *, _nodes=None, ref_table=None)` in `_ast_dynamic_exec_detector.py` — tree-level detector called from `analyze_python()` after `detect_kwargs_unpacking`; when `ref_table` is provided, mutates it in-place (adds `func_ref` entries via `_track_func_ref` and `_track_getattr_ref`); depth-1 (EXEC-006): walks `getattr` Call nodes — (1) if 2nd arg is a `Name` resolving to dangerous name via `_scoped_lookup` → EXEC-006 HIGH; (2) if unresolvable AND 1st arg is sensitive module → EXEC-006 MEDIUM taint sink; depth-2 (EXEC-002): walks Call(func=Attribute(value=Name)) checking ref_table for tracked module refs; depth-3 (EXEC-002): handles bare `Call(func=Name)` on tracked `func_ref` entries; re-exported from `ast_analyzer.py`
- `_SENSITIVE_MODULES` frozenset in `_ast_detectors.py` — set of module names where dynamic attribute access is security-sensitive (`os`, `sys`, `subprocess`, `shutil`, `socket`, `builtins`, `__builtins__`, `importlib`, `ctypes`, `code`, `codeop`); used by `detect_dynamic_exec` for taint-sink classification; re-exported from `ast_analyzer.py`; distinct from `_STAR_IMPORT_EXPANSIONS` in `_ast_imports.py` (which is for star-import expansion, not sensitivity classification)
- `_resolve_first_arg(node, alias_map)` in `_ast_dynamic_exec_detector.py` — resolves the first arg of a `getattr` Call to a module name via `alias_map`; handles `ast.Name` (resolves via alias) and `ast.Attribute` where `.value` is an `ast.Name` (returns outer module name — `getattr(os.path, var)` resolves to `"os"`, which is in `_SENSITIVE_MODULES`); returns `None` for other node types
- `_check_resolved_name` / `_check_taint_sink` in `_ast_dynamic_exec_detector.py` — extracted helpers within the detector; `_check_resolved_name` emits EXEC-006 HIGH when resolved name is in `_DANGEROUS_NAMES`; `_check_taint_sink` emits EXEC-006 MEDIUM when module is in `_SENSITIVE_MODULES` and arg is unresolvable; called from `detect_dynamic_exec` after the `_scoped_lookup` attempt
- `RefEntry` in `_ast_ref_tracker.py` — frozen dataclass with `slots=True`; fields `kind` (`Literal['module', 'func_ref']`) and `resolved` (str, e.g. `'os'`, `'os.system'`); re-exported from `ast_analyzer.py`
- `build_ref_table(tree, alias_map)` in `_ast_ref_tracker.py` — pre-pass that walks assignment nodes tracking `x = __import__('mod')` and `x = importlib.import_module('mod')` patterns; uses `_build_scope_map` for scope-aware keys (`funcname.varname` format, matching `build_symbol_table` convention); recognizes all four patterns in `_IMPORT_CALL_NAMES`; returns `dict[str, RefEntry]`; called in `analyze_python()` after `build_symbol_table`, passed to `detect_dynamic_exec` as `ref_table=`; re-exported from `ast_analyzer.py`
- `_IMPORT_CALL_NAMES` frozenset in `_ast_detectors.py` — canonical set of dynamic import call names (`__import__`, `importlib.import_module`, `builtins.__import__`, `__builtins__.__import__`); used by both `_detect_dynamic_imports` (EXEC-006 emission) and `_detect_inline_import_chain` (inner call check) and `build_ref_table` (assignment tracking); shared by importing from `_ast_detectors`; do NOT duplicate — import from `_ast_detectors`
- `_detect_inline_import_chain` in `_ast_detectors.py` — node-level detector matching `Call(func=Attribute(value=Call, attr=dangerous))` where inner call is in `_IMPORT_CALL_NAMES` and outer attr is in `_INLINE_CHAIN_ATTRS`; emits EXEC-002 CRITICAL; registered in `_DETECTORS` tuple in `ast_analyzer.py`; re-exported from `ast_analyzer.py`
- `_INLINE_CHAIN_ATTRS` frozenset in `_ast_detectors.py` — dangerous attribute names for inline import chain detection (`eval`, `exec`, `system`, `popen`); deliberately excludes `getattr` and `__import__` (those are indirection names, not execution names); distinct from `_EXEC_ATTR_NAMES` in `_ast_dynamic_exec_depth3.py` (same contents but different module)
- `_EXEC_ATTR_NAMES` / `_DANGEROUS_QUALIFIED` in `_ast_dynamic_exec_depth3.py` — `_EXEC_ATTR_NAMES` is `frozenset({'eval', 'exec', 'system', 'popen'})`; `_DANGEROUS_QUALIFIED = _UNSAFE_EXEC_CALLS | _SUBPROCESS_CALLS`; used by `_is_dangerous_ref_attr` for depth-2/3 resolution; one-directional import: `_ast_dynamic_exec_detector.py` imports from `_ast_dynamic_exec_depth3.py`, never reverse
- `_ref_lookup(name, ref_table, scope)` in `_ast_dynamic_exec_depth3.py` — scope-aware lookup in `ref_table` (mirrors `_scoped_lookup` for `RefEntry` values); checks `scope.name` first, falls back to bare `name`
- `_track_getattr_ref(node, ref_table, scope_map, alias_map, file_path)` in `_ast_dynamic_exec_depth3.py` — handles `e = getattr(mod, 'attr')` where `mod` is a tracked module ref; always stores result as `func_ref` in `ref_table`; emits EXEC-002 CRITICAL when attribute is dangerous; called from `_process_assign` in the main detector
- `_check_bare_func_call(node, ref_table, scope_map, file_path)` in `_ast_dynamic_exec_depth3.py` — handles `Call(func=Name)` where `Name` resolves in `ref_table` as a `func_ref` whose `resolved` is dangerous; emits EXEC-002 CRITICAL; called from `_process_call` in the main detector
- `analyze_package(skill_dir, files, findings)` in `package_analyzer.py` — package-level risk facade called from `scanner.py` after all file findings are collected; returns `PackageRiskSummary`; builds role map, scores findings and text signals, applies cross-file correlations, applies multi-role bonus, then maps total score to a risk band
- `ROLE_WEIGHT` / `SEVERITY_POINTS` / `CATEGORY_DRIVER` in `_package_risk_policy.py` — table-driven scoring policy; `ROLE_WEIGHT` maps role strings to multipliers (`entrypoint=1.4`, `script=1.35`, `config=1.1`, `support-doc=0.8`, `reference=0.35`); `SEVERITY_POINTS` maps `Severity` enum values to base points; `CATEGORY_DRIVER` maps finding categories to risk driver labels; extend by adding entries
- `IGNORED_CATEGORIES` in `_package_risk_policy.py` — frozenset of categories excluded from package scoring (`analysis`, `file-safety`, `schema-validation`); extend by adding entries
- `DIRECT_DANGER_DRIVERS` in `_package_risk_policy.py` — frozenset of driver labels that can trigger direct-danger override (`execution`, `exfiltration`, `remote-bootstrap`, `operator-manipulation`); `is_direct_danger()` returns True only when role is `entrypoint`/`script`, driver is in this set, and severity is HIGH/CRITICAL; extend by adding entries
- `_CORRELATION_RULES` in `_package_risk_correlations.py` — table-driven tuple of `(fact_a, fact_b, driver_points_dict)` triples; each matched pair adds points to `driver_scores` and increments the correlated signal count; extend by adding tuples; fact names are resolved by `_collect_facts()`
- `classify_file_role(relative_path)` in `_package_text_roles.py` — maps a package-relative path to one of five roles: `entrypoint` (SKILL.md only), `reference` (any path segment in `_REFERENCE_MARKERS`), `script` (.py/.sh/.bash/.zsh/.ps1/.js/.ts), `config` (.json/.yaml/.yml/.toml/.ini/.cfg/.env/.jinja2), `support-doc` (everything else including .md/.txt/.rst)
- `TextSignal` in `_package_text_signals.py` — frozen dataclass with fields `rule_id`, `severity`, `driver`, `file`, `role`, `suspicious_urls`; used internally by `package_analyzer.py`; NOT a public `Finding` — do not add it to `__init__.__all__` or formatters; pkg rule IDs are PKG-001 (operator coercion), PKG-002 (remote bootstrap), PKG-003 (secret request), PKG-004 (suspicious URL), PKG-005 (setup context URL)
- `PackageRiskSummary` in `models.py` — frozen dataclass added to public API; fields: `score` (int, rounded), `band` (str: `low`/`guarded`/`high`/`severe`), `top_drivers` (tuple of up to 3 driver labels), `counts_by_role` (dict[str, int]), `suspicious_url_count` (int), `correlated_signal_count` (int); exported from `__init__.py`; included in JSON and SARIF output when present

**Invariants**:
- `normalize_text()` in `normalizer.py` applies NFKC normalization (`unicodedata.normalize('NFKC', text)`) as its FIRST step — this decomposes fullwidth Unicode characters (U+FF41-FF5A) and other compatibility characters before zero-width stripping and whitespace canonicalization
- `_handle_assign` in `_ast_symbol_table_assignments.py` iterates ALL targets in `stmt.targets` — multi-target assignments (`a = b = 'eval'`) track every target name with the same resolved value
- Bare `# noqa` does NOT suppress — security scanner requires explicit rule IDs (`# noqa: RULE-ID`)
- `AST-PARSE` and `AST-DEPTH` findings are exempt from `active_ids` filtering — always propagate
- `MAX_AST_RESOLVE_DEPTH = 50` — recursive helpers return `None` at depth > 50
- OBFS-* = obfuscation rules; EXEC-* = malicious code execution rules (distinct namespaces)
- `_make_rot13_finding()` uses `category='obfuscation'` — do NOT reuse `_make_finding` (hardcodes `'malicious-code'`)
- `_process_nested` in `_ast_symbol_table.py` recursively handles arbitrary nesting depth: recurses into inner function bodies BEFORE routing the current level's nonlocal declarations; tracks `own_keys` (set of keys before recursion) so pass-through nonlocal writes from deeper nesting propagate upward past intermediate scopes that don't declare them; do NOT reorder the recursion/routing steps or nonlocal propagation will break
- Deferred imports in `_ast_symbol_table.py` break circular deps — don't reorganize without checking import chains
- `_extract_dict_literal` returns `dict[str, object]` (raw Python constants, not `str()`); `_kwarg_matches` uses native Python truthiness for `bool` table entries and `str()` equality for non-bool entries — `int(0)` is falsy, `str("0")` is truthy
- `_eval_constant_expr` in `_ast_kwargs_dict_tracker.py` resolves `ast.Constant` and `ast.UnaryOp(USub|UAdd, Constant)` to Python values (handles negative int/float literals); returns `_UNRESOLVABLE` sentinel on failure; re-exported from `_ast_kwargs_detector.py`
- `_SHADOW` in `_ast_split_int_list_tracker.py` is a module-level sentinel `list[int]` that marks shadowed (non-int-list) variables in the int-list pre-pass; always compare by identity (`existing is _SHADOW`), never by equality — a legitimate empty list (`codes = []`) must not be confused with a shadow marker
- `_Decls = tuple[set[str], set[str]] | None` in `_ast_split_int_list_tracker.py` — type alias for the optional `(global_names, nonlocal_names)` declarations parameter accepted by mutation helpers and `_walk_fn_body`; `declarations[0]` = global names, `declarations[1]` = nonlocal names; `None` means no declarations (module scope or class body); `_walk_fn_body` defaults to `decls=None, enclosing=""` so module-level and class-level callers need not pass them
- `_walk_fn_body` branch-aware merge rule: `If` branches are two-way (if-body vs else-body); `Match` branches are N-way (one per case); terminal branches (those where `_is_terminal_body` returns True) are excluded from the merge before `_merge_branches` is called — if all branches are terminal the merge receives an empty list (no-op, result stays at pre-branch snapshot); non-exhaustive match always adds the pre-match snapshot as an extra branch; `For`/`While`/`Try`/`With` sub-bodies are walked sequentially (not branch-aware) — they are not mutually exclusive; `break`/`continue` are NOT excluded as terminal (mutations are visible after the loop); `_merge_branches` uses identity (`is`) for `_SHADOW` and value equality (`==`) for concrete int-lists; this invariant must not be changed without updating the corresponding test_int_list_branch_merge.py tests
- `build_alias_map(tree)` recurses into `ast.Try` blocks via `_collect_imports` → `_try_bodies` — imports inside `try/except/else/finally` are captured; do not flatten `tree.body` iteration without preserving this recursion
- `_is_lambda_chr(node)` in `_ast_split_map_resolver.py` validates exactly: single positional arg, no vararg, no kwonly args, body is `chr(arg)` with matching param name — do not relax these checks without a test for the edge case
- `_deduplicate()` in `content_scanner.py` prefers AST findings over regex when both exist for the same `(rule_id, line)` key — AST findings carry more precise severity and matched_text from symbol-table resolution; regex-only and AST-only findings are preserved as-is; do NOT revert to regex-preferred order or AST precision will be masked
- `_detect_subprocess_list_exfil` uses `Finding()` directly with `category='data-exfiltration'` — do NOT use `_make_finding` (hardcodes `'malicious-code'`); follows the same constraint as `_make_rot13_finding()`
- `_detect_dns_exfil` uses `Finding()` directly with `category='data-exfiltration'` — same constraint; flags `socket.getaddrinfo()` only when first arg is NOT a plain string constant (f-strings, variables, and concatenation all trigger)
- `_resolve_format_map_call` in `_ast_split_format_map.py` is registered in `resolve_call()` after `_resolve_format_call`; format_map resolves `template.format_map(dict_expr)` via `_extract_dict_literal` or symbol table lookup
- `_resolve_slice_expr` rejects `step == 0` (invalid) but permits `step == -1` (string reversal `[::-1]`) — step guard is `step is not None and step == 0`, not `step <= 0`
- `_detect_custom_rot13` requires BOTH a lowercase branch (`'a'`/`'z'` sentinels) AND an uppercase branch (`'A'`/`'Z'` sentinels) inside the function body, plus `% 26` arithmetic with `chr`/`ord` calls — all three conditions required to minimize false positives on general chr/ord code
- `_multiline_pi_findings` in `rules/_multiline_pi.py` — sliding window of 3, 4, 5 consecutive lines joined with space; applies only `category == 'prompt-injection'` rules; deduplicates against `existing` findings by `(rule_id, any_line_in_window)`; findings attributed to first line of window; called from `_line_phase_findings`
- `_build_bytes_table` pre-pass in `_ast_split_bytes.py` — tracks `name = bytes.fromhex(...)` variable assignments for use in split-evasion; inline `(bytes.fromhex('XX') + bytes.fromhex('YY')).decode()` is resolved without symbol table (symbol_table is `dict[str, str]`, cannot hold bytes objects); `resolve_fromhex_concat` accepts optional `symbol_table` kwarg so `bytes.fromhex(var)` resolves `var` via symbol table lookup
- `_build_scope_map` in `_ast_split_detector.py` — maps class body statements (non-method) to `ClassName` scope in addition to methods; class-level join/concat nodes now get the correct scope for symbol table lookups (`ClassName.var` keys)
- `_handle_assign` in `_ast_symbol_table_assignments.py` resolves `BinOp(Add)` of two tracked `Name` references eagerly before storing — class-level `func_name = prefix + suffix` resolves to the concatenated string without requiring a second `_resolve_indirections` pass
- `_handle_string_list_literal` and `_handle_dict_literal` live in `_ast_symbol_table_dict_tracker.py` — import them from the dict-tracker module
- `_resolve_binop_concat` in `_ast_split_int_list_tracker.py` — resolves `codes = part1 + part2` where both operands are tracked int-lists in the pre-pass result dict; called from `_handle_assign` when RHS is `BinOp(Add)` of two `Name` nodes
- `_extend_with_tracked_var` in `_ast_split_int_list_tracker.py` — extends a tracked int-list with the contents of another tracked variable; called from `_extend_tracked` when the extension value is an `ast.Name`; shadows target if source is untracked
- EXEC-011 TOML entry has `patterns = []` — detection is AST-only via `_detect_dunder_chain`; do not add regex patterns (the chain structure requires AST traversal)
- `_detect_dunder_chain` uses `Finding()` directly — do NOT use `_make_finding` because `_ast_detectors.py` is frozen (349/350 lines) and `_RECOMMENDATIONS` cannot be extended; this follows the same constraint as `_detect_subprocess_list_exfil` and `_detect_dns_exfil`
- `_dunder_inner = True` marker on `ast.Attribute` nodes — set by `_detect_dunder_chain` on inner nodes of a multi-node chain; `_detect_dunder_chain` checks `getattr(node, "_dunder_inner", False)` first and returns `[]` immediately if set; this prevents the same chain from emitting N findings (one per dangerous Attribute) when `ast.walk` visits each node
- `_detect_dunder_chain` severity rule: CRITICAL if any dunder in the chain is in `EXEC_ESCAPE_DUNDERS`; HIGH if all dunders are from `MRO_WALK_DUNDERS` only; minimum chain length is 2 dangerous dunders
- OBFS-001 TOML entry has `patterns = []` — detection is AST-only via `_detect_rot13_codec`, `_detect_rot13_maketrans`, and `_detect_custom_rot13`; do not add regex patterns (AST handles this more accurately)
- `final_band()` in `_package_risk_policy.py` applies direct-danger overrides AFTER `risk_band()` maps the numeric score; `severe_direct_danger` (HIGH/CRITICAL signal in entrypoint/script) forces band to `severe`; `direct_danger` (any qualifying signal) raises band from `low`/`guarded` to `high`; do NOT bypass `final_band()` by calling `risk_band()` directly
- `_format_package_risk()` in `formatters.py` renders the `PackageRiskSummary` block in text output (both default and verbose modes); quiet mode does NOT include package risk — it prints the verdict line only
- `_serialize_package_risk()` in `json_formatter.py` serializes `PackageRiskSummary` to JSON; returns `None` when `result.package_risk is None`; `top_drivers` serialized as a list, `counts_by_role` as a plain dict
- Package risk output in SARIF is written to `run.properties.skillScanPackageRisk` (camelCase keys: `band`, `score`, `topDrivers`, `countsByRole`, `suspiciousUrlCount`, `correlatedSignalCount`)
- `deduplicate_signals()` in `_package_text_signal_utils.py` deduplicates by `(rule_id, file, driver)` triple — same signal type from the same file for the same driver is counted only once; called inside `build_text_signals()` before returning
- `is_warning_like_reference()` in `_package_text_signal_utils.py` — suppresses coercion, secret, and remote signals for `reference`-role files whose content matches `WARNING_CONTEXT_RE`; prevents false positives from security-warning documentation
- `detect_dynamic_exec` mutates `ref_table` in-place when provided — `_track_func_ref` and `_track_getattr_ref` add `func_ref` entries during the walk; callers that need an unmodified copy must pass `dict(ref_table)` instead; `build_ref_table` (the pre-pass) is always called first in `analyze_python()` and produces only `module` entries — `func_ref` entries are added exclusively by `detect_dynamic_exec`
- `ref_table` is a parallel `dict[str, RefEntry]` — it is NEVER merged into or read from `symbol_table` (`dict[str, str]`); they use the same scope-key convention (`funcname.varname`) but track different things: `symbol_table` tracks string values, `ref_table` tracks module/function references; do NOT extend `symbol_table` to hold non-string values
- `ast.walk` BFS order guarantees Assign nodes are visited before sibling Call nodes at the same nesting level — `detect_dynamic_exec` relies on this: `_track_func_ref` / `_track_getattr_ref` run on Assign to populate `ref_table` before `_check_ref_call` / `_check_bare_func_call` run on Call; do NOT switch to DFS traversal or reverse the node order

**Known debt**:
- PEP 448 spread dicts (`{**base, ...}`) in kwargs are conservatively treated as unresolvable (no tracking planned)
- `_ast_split_resolve.py` is at 222/350 lines — has headroom after format_map extraction to `_ast_split_format_map.py`
- `_ast_split_format.py` is at 299/350 lines — effectively frozen; any addition requires offsetting removal first
- `_ast_imports.py` is at 160/350 lines — has headroom after string-resolver extraction to `_ast_string_resolver.py`
- `_ast_rot13.py` is at 247/350 lines — has headroom after branch analysis extraction to `_ast_rot13_branch_analysis.py`
- `_ast_symbol_table.py` is at 299/350 lines — effectively frozen; any future addition requires extracting a helper to a sibling module
- `_ast_split_comprehension.py` is at 265/350 lines — 35 lines remaining (reduced after inlining `_collect_int_lists_from_body` into `_collect_int_list_assigns`)
- `_ast_symbol_table_assignments.py` is at 288/350 lines — 12 lines remaining
- `_ast_split_star_unpack.py` is at ~79/350 lines — ample room
- `_ast_symbol_table_dict_tracker.py` is at ~149/350 lines — ample room
- `collect_loop_assigns` supports only inline string-literal lists and local list-literal name references as iter source — tracked list variables from symbol_table are NOT supported (symbol_table is `dict[str, str]`, cannot hold lists)
- `_maybe_flatten_starred` in `_ast_split_star_unpack.py` handles `ast.Name`, `ast.Attribute` (single-level), and `ast.Subscript` (constant key) — nested attributes and computed expressions are not supported
- DEBT-035-TRY-EXCEPT-BRANCH-MERGE: `_walk_fn_body` walks `Try`/`except` sub-bodies sequentially (not branch-aware); `except` handlers are not mutually exclusive with the `try` body, so this is conservative but could produce merged int-lists when a variable is assigned differently in `try` vs `except`; fixing this requires understanding Python exception semantics (partial execution of try body) and is out of scope for PLAN-035
- `_ast_split_int_list_tracker.py` is at 291/350 lines — 9 lines remaining; `_is_exhaustive_match` moved to `_ast_terminal_body.py` in PLAN-036 which freed the lines previously used by that function
- `package_analyzer.py` is at ~107/350 lines — ample room
- `_package_text_signals.py` is at ~147/350 lines — ample room
- `_package_risk_correlations.py` is at ~80/350 lines — ample room
- PKG-* rule IDs are used internally by `TextSignal` only — they do not appear in the rules catalog (`rules/data/`) and are not subject to `suppress_rules` config; no TOML entries exist for them
- `_ast_dynamic_exec_detector.py` is at 264/350 lines — 86 lines remaining after PLAN-038 Parts C+D
- `_ast_dynamic_exec_depth3.py` is at ~174/350 lines — ample room
- `_ast_ref_tracker.py` is at ~103/350 lines — ample room
- `_ast_detectors.py` is at 349/350 lines — effectively frozen; any future addition requires extracting a helper to a sibling module (reached from 311 after PLAN-038 Part A additions)
- `_ast_dunder_chain_detector.py` is at 153/350 lines — ample room
- Known false-positive pathway in `detect_dynamic_exec`: `getattr(os.path, var)` fires MEDIUM because `_resolve_first_arg` returns `"os"` (outer module name) which is in `_SENSITIVE_MODULES`; `getattr(sys, var)` fires MEDIUM because `sys` is in `_SENSITIVE_MODULES` even though many `sys` attributes are benign; both are intentional (MEDIUM not HIGH — uncertain threat)
- Class-method local variables are not in the symbol table for `detect_dynamic_exec` resolution — `_process_class` in `_ast_symbol_table.py` does not export method-local vars; only module-level and class-level (non-method) vars resolve
- `_INLINE_CHAIN_ATTRS` in `_ast_detectors.py` is missing subprocess family names (`call`, `run`, `Popen`) — these inline chains are only caught by depth-2 ref_table detection, not by the inline chain node-level detector; filed as improvement in PLAN-038
- `build_ref_table` tracks only single-assignment patterns (`x = __import__('mod')`) — augmented assignment (`x += ...`), tuple unpack, and walrus operator patterns are not tracked; depth-4+ alias chains (`g = f; g('cmd')`) are not tracked

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
