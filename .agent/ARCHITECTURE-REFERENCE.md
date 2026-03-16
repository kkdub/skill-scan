# Architecture Reference

Detailed module-level documentation for skill-scan internals. For key patterns and invariants, see the Architecture Notes section in `CLAUDE.md`.

## Scanner Pipeline

- `content_scanner.scan_all_files()` returns a 4-tuple: `(findings, bytes_scanned, files_skipped, suppressed_count)`
- Concurrent scanning uses `ProcessPoolExecutor` when file count >= `MIN_FILES_FOR_CONCURRENCY` (8); falls back to sequential on `OSError`/`RuntimeError`
- `ScanConfig.max_workers`: `0` = auto-detect (capped at 8), positive = explicit worker count (also capped at 8)
- `ScanResult.suppressed_count`: count of findings removed by inline `# noqa: RULE-ID` comments; default `0`
- `match_content()` in `engine.py` is a public wrapper with no `_depth` parameter; `_match_content_recursive()` is the private implementation that carries `_depth`

## AST Analyzer

- `analyze_python()` returns an `AST-PARSE` INFO finding on `SyntaxError`/`ValueError`/`RecursionError` during parsing; returns an `AST-DEPTH` INFO finding (plus any accumulated findings) on `RecursionError` during tree walking
- `AST-PARSE` and `AST-DEPTH` findings are exempt from `active_ids` filtering in `content_scanner._apply_rules()` — they always propagate to output
- `MAX_AST_RESOLVE_DEPTH = 50` in `_ast_helpers.py` — recursive string-resolution helpers return `None` instead of crashing at depth > 50
- `build_alias_map(tree)` in `_ast_helpers.py` returns `dict[str, str]` mapping local alias to canonical module name; called by `analyze_python()` and threaded to all `_detect_*` functions via `alias_map` kwarg
- `get_call_name(node, alias_map=None)` resolves aliased call names (e.g. `c.encode` with `alias_map={'c': 'codecs'}` → `'codecs.encode'`); all `_detect_*` functions accept `alias_map` kwarg (empty-dict default, backward-compatible)
- `ast_analyzer.py` uses a `_DETECTORS` tuple to register all detector functions; current detectors: `_detect_unsafe_calls`, `_detect_dynamic_imports`, `_detect_unsafe_deserialization`, `_detect_string_concat_evasion`, `_detect_dynamic_access`, `_detect_decorator_evasion`, `_detect_rot13_codec`, `_detect_rot13_maketrans`; add new detectors to this tuple
- `analyze_python()` also calls `build_symbol_table(tree)`, `detect_split_evasion(tree, file_path, alias_map, symbol_table)`, and `detect_kwargs_unpacking(tree, file_path, alias_map, symbol_table)` separately from the `_DETECTORS` loop — tree-level detectors that need the full symbol table go here, not in `_DETECTORS`

## Symbol Table

- `build_symbol_table(tree: ast.Module) -> dict[str, str]` — two-pass pre-pass returning a flat dict of variable-to-string mappings; Pass 1: variable assignment tracking; Pass 2: return-value extraction (stores converged function return values under `"funcname()"` / `"ClassName.method()"` composite keys) then call-site resolution (`_resolve_call_assignments`); function-scoped variables are prefixed `"funcname.varname"`; class attributes stored as `"ClassName.attr"` at module scope; bounded by `MAX_RESOLVE_DEPTH = 50`; circular references are dropped silently
- Tracks dict subscript assignments (`d['key'] = 'val'`), list-index subscript assignments (`parts[0] = 'ev'`), dict literal initializers, and `BinOp(Mult)` string repetition
- Handles `global`/`nonlocal` declarations via pre-pass (`_collect_scope_declarations`)
- Composite key format `'varname[key]'` (brackets) prevents collision with plain variable names; integer index `0` and string key `'0'` produce the same composite key `'varname[0]'` (documented collision edge case, not guarded)
- `_Ref` sentinel class marks unresolved variable references during the pre-pass; resolved to `str` or dropped before `build_symbol_table()` returns
- `_ast_symbol_table_helpers.py` imports are deferred inside `_collect_assignments()` to break circular import (`_ast_symbol_table_helpers.py` imports `_Ref` from `_ast_symbol_table.py`)
- `_route_globals()` moves global-declared writes from function scope to module-level result dict (last-write-wins); also updates `module_scope` so subsequent function scopes see routed values
- `_process_nested()` handles nested functions: routes global writes to module-level, nonlocal writes to enclosing scope
- `_process_class()` walks `ClassDef` nodes: class-level assignments as `'ClassName.attr'`, `self.attr = 'val'` patterns via `_handle_self_attr_assign()`, method return values under `'ClassName.method()'`
- `_resolve_call_assignments()` — post-pass over module-level `ast.Assign` nodes resolving `x = func()` when `"func()"` is tracked
- `_get_call_key(call)` maps a `Call` node to composite key: `"funcname()"` or `"ClassName.method()"`

## Return-Value Tracking

- `_collect_return_value(func_body, scope) -> str | None` returns the converged string when ALL return paths resolve to the same constant, or `None` otherwise (conservative)
- Checks for implicit fallthrough via `_has_implicit_fallthrough()`/`_definitely_returns()`; handles `if/elif/else`, `try/except/else/finally`, `with`, and `match` blocks
- Only resolves `ast.Constant`, `ast.Name` (scope lookup), and `ast.BinOp(Add)` — complex returns are not tracked (conservative)
- `_sub_bodies()` in `_ast_symbol_table_return_helpers.py` is the DRY source — `_ast_symbol_table_class_helpers.py` imports it from there

## Split-Evasion Detector

- `detect_split_evasion()` reconstructs strings via: `BinOp(Add)`, f-string interpolation, `"".join(...)`, `'template'.format(...)`, `'%s%s' % (a, b)`, `.replace()` chains, `functools.reduce()` concat, dict/list subscript lookups, `ast.Attribute` (`self.attr`), `ast.Call` (return values), `reversed()` join, `chr()`/`ord()` chains, bytes-constructor patterns, comprehension `chr()` mapping, and dynamic dispatch via introspection subscripts
- Emits EXEC-002 for dangerous names (eval, exec, system, popen), EXEC-006 for dynamic import names (`__import__`, `getattr`); also bridges to decoder for split encoded payloads
- `_RESOLVERS` — tuple of `(predicate, resolver)` pairs; `_try_resolve_split()` iterates and returns first non-`None` result; all resolvers share signature `(node, symbol_table, scope, *, alias_map=None) -> str | None`; add new resolvers here
- `_NAME_RULE` maps dangerous names to `(rule_id, severity, description_prefix)`
- `_DECORATOR_RULE` in `_ast_detectors.py` mirrors `_NAME_RULE` locally to avoid import cycle

## Split-Evasion Sub-modules

- `_ast_split_resolve.py` — expression resolution helpers (`resolve_binop_chain`, `resolve_operand`, `resolve_fstring`, `resolve_expr`, `resolve_call_return`, `resolve_call`); re-exports from `_ast_split_bytes`, `_ast_split_reduce`, `_ast_split_helpers`
- `resolve_expr()` — resolves `ast.Name`, `ast.Attribute`, `ast.Subscript`, `ast.Call`; Attribute resolution gated to `self`/`cls`.attr and `ClassName.attr` only
- `resolve_call_return()` — resolves calls via parentheses-suffix composite key; handles `func()` and `self.method()` / `ClassName.method()`
- `resolve_call()` — registry-compatible wrapper chaining join, format, bytes-constructor, reduce, and call-return resolvers
- `_resolve_replace_chain()` — walks `.replace()` chains up to 20 levels deep
- `_ast_split_chr.py` — resolves `chr(N)`, `chr(ord('x'))`, `chr(ord('x') + N)`; `_MAX_INT_DEPTH = 50`
- `_ast_split_bytes.py` — resolves `bytearray(b'...').decode()`, `str(b'...', 'utf-8')`, `codecs.decode(b'...', 'utf-8')`; gates on literal bytes arguments only
- `_ast_split_reduce.py` — resolves `functools.reduce(lambda a,b: a+b, [...])` and `functools.reduce(operator.add/concat, [...])`
- `_ast_split_helpers.py` — format/%-format resolution; `_scoped_lookup`, `_resolve_join_elements`, `_resolve_subscript_expr`, `_resolve_slice_expr`; `_PERCENT_SPEC_RE` matches all standard %-specifiers with `(?<!%)` lookbehind
- `_ast_split_join_helpers.py` — `_resolve_join_call()` dispatches to list/tuple, comprehension, reversed, or map resolvers; `map()` limited to `chr()` and `str()` only

## Dynamic Dispatch Detection

- `_check_dynamic_dispatch()` detects `globals()['eval']`, `vars(obj)['eval']`, `obj.__dict__['eval']`, and two-level chaining
- `_INTROSPECTION_FUNCS = frozenset({"vars", "globals", "locals"})`
- `_is_introspection_base()` checks `ast.Call` to introspection func or `ast.Attribute` with `attr == '__dict__'`
- `_extract_subscript_key()` resolves subscript key from `ast.Constant` or `ast.Name` via `_scoped_lookup`

## Kwargs Unpacking Detector

- `detect_kwargs_unpacking()` detects dangerous keyword arguments via `**` unpacking (e.g. `subprocess.run(**opts)` where `opts={'shell': True}`)
- `_DANGEROUS_KWARGS` — table-driven config mapping function-name prefixes to `(kwarg_key, kwarg_value, rule_id, severity, description_prefix)` tuples; extend by adding entries
- `_collect_dict_assigns(tree)` — pre-pass collecting module-level dict assignments; tracks all constant value types converted to strings

## Decoder

- `decode_payload()` has two return paths: bytes→UTF-8 for `base64`/`hex`; direct `str` for `url`/`unicode_escape` (via `_decode_str_payload()`)
- `_decode_unicode_escape()` strips lone surrogates (U+D800–U+DFFF) to prevent surrogate-interspersed evasion
- `_decode_url_encoded()` strips null bytes (`\x00`) to prevent null-byte-interspersed evasion
- `EncodedPayload.encoding_type` accepts `'base64'` | `'hex'` | `'url'` | `'unicode_escape'`

## ROT13 Detection

- `_ast_rot13.py` uses its own `_make_rot13_finding()` with `category='obfuscation'` — do NOT reuse `_make_finding` from `_ast_detectors.py` which hardcodes `category='malicious-code'`
- `is_rot13_pair(from_str, to_str) -> bool` is a public pure function; re-exported from `ast_analyzer.py`

## Known Limitations

- Return-value tracking: method returning via `self.attr` is NOT tracked (conservative gap); `_resolve_call_assignments` handles module-level `x = func()` only; only same-module calls resolved
- DEBT-025-DICT-MERGING — dict merging patterns (`{**base, 'shell': True}`, `opts | {'shell': True}`) not handled by kwargs detector's `_collect_dict_assigns`
- DEBT-024-TRACKED-COMPREHENSION — `''.join(chr(c) for c in codes)` where `codes` is a tracked variable requires symbol table extension to support non-string values

## Evasion Corpus

Test fixtures at `tests/fixtures/split_evasion/` — positive (`pos_`) files should detect, negative (`neg_`) should not trigger. Corpus test filter uses `rule_id` matching (`f.rule_id in ('EXEC-002', 'EXEC-006')`). Format/%-format fixtures use `UP030`/`UP031`/`UP032` ruff ignores (intentional old-style syntax).
