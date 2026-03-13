# skill-scan

Security scanner for agent skills — detect prompt injection, malicious code, and data exfiltration before installation.

## Quick Reference

- **Plans & specs**: `.agent/plans/`
- **Code patterns and rules**: `.agent/standards/`
- **Workflow context**: `.agent/WORKFLOW.md`

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
- **Max 300 lines per file** (source code in `src/` and `tests/`)

## Project Structure

```
src/skill_scan/           # Production source code
  ast_analyzer.py         # Facade: analyze_python() entry point + re-exports from _ast_detectors + _ast_rot13 + _ast_symbol_table + _ast_split_detector
  _ast_detectors.py       # Private detector functions (_detect_* and _make_finding)
  _ast_helpers.py         # Private string-resolution helpers + build_alias_map + get_call_name; re-exports from _ast_join_helpers
  _ast_join_helpers.py    # Private join-resolution helpers extracted from _ast_helpers
  _ast_rot13.py           # ROT13 AST detectors (is_rot13_pair, _detect_rot13_codec, _detect_rot13_maketrans)
  _ast_symbol_table.py    # Symbol table builder (build_symbol_table); pre-pass variable-to-string mapping with scope isolation; _Ref sentinel; _collect_assignments uses deferred import of _ast_symbol_table_helpers to break circular import; handles ClassDef walking (_process_class), global/nonlocal routing (_route_globals, _process_nested)
  _ast_symbol_table_helpers.py  # Private assignment-tracking helpers extracted from _ast_symbol_table.py (_walk_body, _process_stmt, _recurse_control_flow, _collect_walrus, _handle_assign, _handle_unpack, _track_name_assign, _handle_aug_assign, _resolve_binop_mult, _handle_subscript_assign, _handle_dict_literal, _collect_scope_declarations, _handle_self_attr_assign)
  _ast_symbol_table_class_helpers.py  # Private class-attribute helpers (_walk_self_attrs, _check_self_assign, _sub_bodies); handles self.attr = 'val' tracking inside method bodies
  _ast_split_detector.py  # Split-evasion detector (detect_split_evasion); reconstructs concat/f-string/join/format/%-format/subscript/Attribute payloads; _build_scope_map now walks ClassDef method bodies
  _ast_split_helpers.py   # Private format/%-format resolution helpers (_resolve_format_call, _resolve_percent_format, _resolve_expr_list, _resolve_join_elements, _resolve_subscript_expr, _resolve_subscript_key, _resolve_single_expr, _scoped_lookup); re-exports from _ast_split_join_helpers
  _ast_split_resolve.py   # Expression resolution helpers extracted from _ast_split_detector.py (resolve_binop_chain, resolve_operand, resolve_fstring, resolve_expr, _resolve_subscript_lookup); Facade Re-export Pattern
  _ast_split_join_helpers.py    # Private generator/map join resolution helpers (_resolve_generator_join, _resolve_map_join, _resolve_map_chr, _resolve_map_str)
  decoder.py              # Facade: EncodedPayload, public constants, extract/decode + re-exports from _decoder_helpers + _decoder_url_unicode
  _decoder_helpers.py     # Private regex constants and extraction/decode helpers (base64, hex)
  _decoder_url_unicode.py # Private URL/unicode-escape extraction and decode helpers
  content_scanner.py      # File I/O + rule dispatch + AST deduplication + concurrent scanning
  suppression.py          # Inline noqa suppression (public: parse_noqa, filter_suppressed)
  rules/data/
    obfuscation.toml      # OBFS-002..OBFS-005 URL-encoding and unicode-escape rules
tests/                    # Test suite (mirrors src/ structure)
scripts/                  # Quality & analysis scripts
.agent/                   # Plans, standards, workflow
Dockerfile                # Containerized scanner (python:3.13-slim, non-root user 'scanner')
.dockerignore             # Excludes dev/build artifacts from Docker context
```

## Architecture Notes

- `content_scanner.scan_all_files()` returns a 4-tuple: `(findings, bytes_scanned, files_skipped, suppressed_count)`
- Concurrent scanning uses `ProcessPoolExecutor` when file count >= `MIN_FILES_FOR_CONCURRENCY` (8); falls back to sequential on `OSError`/`RuntimeError`
- `ScanConfig.max_workers`: `0` = auto-detect (capped at 8), positive = explicit worker count (also capped at 8)
- `ScanResult.suppressed_count`: count of findings removed by inline `# noqa: RULE-ID` comments; default `0`
- Bare `# noqa` (no rule ID) does NOT suppress — security scanner requires explicit IDs
- `analyze_python()` returns an `AST-PARSE` INFO finding on `SyntaxError`/`ValueError`/`RecursionError` during parsing; returns an `AST-DEPTH` INFO finding (plus any accumulated findings) on `RecursionError` during tree walking
- `AST-PARSE` and `AST-DEPTH` findings are exempt from `active_ids` filtering in `content_scanner._apply_rules()` — they always propagate to output
- `MAX_AST_RESOLVE_DEPTH = 50` in `_ast_helpers.py` — recursive string-resolution helpers return `None` instead of crashing at depth > 50
- `match_content()` in `engine.py` is a public wrapper with no `_depth` parameter; `_match_content_recursive()` is the private implementation that carries `_depth`
- `ast_analyzer.py` and `decoder.py` are facade modules — they re-export all names from their sibling `_ast_detectors.py`/`_ast_rot13.py`/`_ast_symbol_table.py`/`_ast_split_detector.py` and `_decoder_helpers.py`/`_decoder_url_unicode.py` respectively (Facade Re-export Pattern); `_ast_split_detector.py` also re-exports from `_ast_split_resolve.py`
- `build_alias_map(tree)` in `_ast_helpers.py` returns `dict[str, str]` mapping local alias to canonical module name; called by `analyze_python()` and threaded to all `_detect_*` functions via `alias_map` kwarg
- `get_call_name(node, alias_map=None)` resolves aliased call names (e.g. `c.encode` with `alias_map={'c': 'codecs'}` → `'codecs.encode'`); all `_detect_*` functions accept `alias_map` kwarg (empty-dict default, backward-compatible)
- `ast_analyzer.py` uses a `_DETECTORS` tuple to register all detector functions; add new detectors to this tuple
- `analyze_python()` also calls `build_symbol_table(tree)` and `detect_split_evasion(tree, file_path, alias_map, symbol_table)` separately from the `_DETECTORS` loop — tree-level detectors that need the full symbol table go here, not in `_DETECTORS`
- `build_symbol_table(tree: ast.Module) -> dict[str, str]` in `_ast_symbol_table.py` — pre-pass that returns a flat dict of variable-to-string mappings; function-scoped variables are prefixed `"funcname.varname"`; class attributes stored as `"ClassName.attr"` at module scope; bounded by `MAX_RESOLVE_DEPTH = 50`; circular references are dropped silently; tracks dict subscript assignments (`d['key'] = 'val'`) and list-index subscript assignments (`parts[0] = 'ev'`) as composite keys (`'varname[key]'`); tracks dict literal initializers and resolves `BinOp(Mult)` string repetition; handles `global`/`nonlocal` declarations via pre-pass (`_collect_scope_declarations`)
- `_ast_symbol_table_helpers.py` — private module with all assignment-tracking helpers used by `_collect_assignments()`; `_ast_symbol_table.py` imports these via a deferred local import inside `_collect_assignments()` to break the circular import that would otherwise result from `_ast_symbol_table_helpers.py` importing `_Ref` from `_ast_symbol_table.py`; also contains `_collect_scope_declarations(body)` and `_handle_self_attr_assign()` (delegates to `_ast_symbol_table_class_helpers.py`)
- Composite key format `'varname[key]'` (brackets) in the symbol table represents both dict subscript entries (`d['key'] = 'val'`) and list-index entries (`parts[0] = 'ev'`) — brackets prevent collision with plain variable names; integer index `0` and string key `'0'` produce the same composite key `'varname[0]'` (documented collision edge case, not guarded)
- `_resolve_binop_mult(node)` in `_ast_symbol_table_helpers.py` — resolves `string * positive-int` (and `int * string`) to the repeated string; only resolves when integer >= 1; skips 0, negative, and float operands
- `_collect_scope_declarations(body) -> tuple[set[str], set[str]]` in `_ast_symbol_table_helpers.py` — collects `global` and `nonlocal` declared names from a function body (walks immediate body plus if/else branches, does not recurse into nested functions); returns `(global_names, nonlocal_names)`
- `_route_globals(func_scope, global_names, result, module_scope=None)` in `_ast_symbol_table.py` — moves global-declared writes from function scope to the module-level result dict (last-write-wins); also updates `module_scope` so subsequent function scopes resolving against it see routed values; removes the function-prefixed key to prevent duplicates
- `_process_nested(body, parent_scope, result)` in `_ast_symbol_table.py` — handles nested functions: routes global-declared writes to module-level result dict and nonlocal-declared writes to the enclosing function scope; stores remaining inner-scope entries under `"funcname.varname"`
- `_process_class(node, module_scope, result)` in `_ast_symbol_table.py` — walks a `ClassDef` node: collects class-level assignments prefixed as `'ClassName.attr'`; then iterates methods and calls `_handle_self_attr_assign()` to capture `self.attr = 'val'` patterns also as `'ClassName.attr'`
- `detect_split_evasion(tree, file_path, alias_map, symbol_table) -> list[Finding]` in `_ast_split_detector.py` — reconstructs strings assembled via `BinOp(Add)`, f-string interpolation, `"".join(...)`, `'template'.format(...)`, `'%s%s' % (a, b)`, dict subscript lookups, list-index subscripts, and `ast.Attribute` (`self.attr`) using the symbol table; emits EXEC-002 for dangerous names (eval, exec, system, popen), EXEC-006 for dynamic import names (`__import__`, `getattr`); also bridges to decoder for split encoded payloads
- `_resolve_join_call(node, symbol_table, scope, alias_map)` in `_ast_split_detector.py` — now accepts `alias_map` parameter (threaded from all call sites); dispatches to `_resolve_join_elements` (list/tuple), `_resolve_generator_join` (generator expression), or `_resolve_map_join` (map(chr/str)) depending on join argument type
- `resolve_fstring()` in `_ast_split_resolve.py` processes `ast.FormattedValue` by resolving `value.value` directly via `resolve_expr()`, ignoring `conversion` (!s/!r) and `format_spec` fields; evasion via `f'{x!r}'` is detected
- `_resolve_subscript_lookup(node, symbol_table, scope)` in `_ast_split_resolve.py` — resolves `ast.Subscript` (dict key or integer list index) to a string via composite key lookup; delegates to `_resolve_subscript_expr` in `_ast_split_helpers.py`; re-exported from `_ast_split_detector.py` (Facade Re-export Pattern)
- `resolve_expr(node, symbol_table, scope)` in `_ast_split_resolve.py` — resolves `ast.Name`, `ast.Attribute`, or `ast.Subscript` to a string; Attribute resolution is gated to `self`/`cls`.attr (looked up as `scope.attr`) and direct `ClassName.attr` patterns only — arbitrary `obj.attr` is rejected to prevent false positives
- `resolve_binop_chain`, `resolve_operand`, `resolve_fstring` in `_ast_split_resolve.py` — expression resolution helpers extracted from `_ast_split_detector.py` for SIZE-001 compliance; re-exported from `_ast_split_detector.py`
- `_NAME_RULE` in `_ast_split_detector.py` is a lookup table mapping each dangerous name to `(rule_id, severity, description_prefix)` — use this pattern when one detector must emit different rule IDs per matched name
- `_ast_split_helpers.py` — private module with format/%-format resolution helpers; `_resolve_format_call(node, symbol_table, scope)` handles `'template'.format(a, b)` (gates on string-constant receiver); `_resolve_percent_format(node, symbol_table, scope)` handles `'%s%s' % (a, b)` (gates on string-constant LHS, avoids integer modulo); `_PERCENT_SPEC_RE` matches all standard %-specifiers (`%s %d %f %r %x %o %e %g %c %a %i`) with `(?<!%)` lookbehind to exclude `%%`; `_substitute_percent()` returns `None` when `len(values) > placeholder count` (over-provisioning defense); `_scoped_lookup`, `_resolve_join_elements`, `_resolve_subscript_expr`, `_resolve_subscript_key`, and `_resolve_single_expr` live here; `_resolve_single_expr` gates `ast.Attribute` resolution to `self`/`cls`.attr and `ClassName.attr` patterns only (prevents false positives on arbitrary `obj.attr`); `_resolve_subscript_key(slice_val)` converts string key or non-negative int to composite key suffix; re-exports `_resolve_generator_join` and `_resolve_map_join` from `_ast_split_join_helpers.py`
- `_ast_split_join_helpers.py` — private module with generator expression and map() resolution helpers; `_resolve_generator_join(gen, sep, symbol_table, scope)` handles `x for x in [...]` identity generators; `_resolve_map_join(call, sep, alias_map)` dispatches to `_resolve_map_chr` (int literals → characters) or `_resolve_map_str` (string passthrough); `map()` support is limited to `chr()` and `str()` only
- `_Ref` sentinel class in `_ast_symbol_table.py` marks unresolved variable references during the pre-pass; resolved to `str` or dropped before `build_symbol_table()` returns
- Evasion corpus at `tests/fixtures/split_evasion/` — 37 positive (should detect) and 4 negative (should not trigger) Python fixture files; prefix `pos_` / `neg_`; format/%-format fixtures use `UP030`/`UP031`/`UP032` ruff ignores (intentional old-style format syntax); Plan 021 added 7 fixtures: `pos_list_index_concat.py`, `pos_list_index_mutate.py`, `pos_global_overwrite.py`, `pos_nonlocal_overwrite.py`, `pos_class_level_attr.py`, `pos_class_self_attr.py`, `pos_class_cross_method.py`
- `decode_payload()` in `decoder.py` has two return paths: bytes→UTF-8 for `base64`/`hex`; direct `str` for `url`/`unicode_escape` (via `_decode_str_payload()`)
- `_decode_unicode_escape()` in `_decoder_url_unicode.py` strips lone surrogate characters (U+D800–U+DFFF) from the decoded output to prevent surrogate-interspersed evasion; uses a generator expression filtering `0xD800 <= ord(c) <= 0xDFFF`
- `_decode_url_encoded()` in `_decoder_url_unicode.py` strips null bytes (`\x00`) from the decoded output via `.replace('\x00', '')` to prevent null-byte-interspersed evasion
- `EncodedPayload.encoding_type` accepts `'base64'` | `'hex'` | `'url'` | `'unicode_escape'`
- OBFS-* is the rule namespace for obfuscation detection (distinct from EXEC-* for malicious code execution); OBFS-001 is AST-based (ROT13), OBFS-002..005 are regex-based in `obfuscation.toml`
- `_ast_rot13.py` uses its own `_make_rot13_finding()` with `category='obfuscation'` — do NOT reuse `_make_finding` from `_ast_detectors.py` which hardcodes `category='malicious-code'`
- `is_rot13_pair(from_str, to_str) -> bool` in `_ast_rot13.py` is a public pure function; re-exported from `ast_analyzer.py`

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
