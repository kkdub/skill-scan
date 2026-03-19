# Architecture Reference

Detailed module-level documentation for skill-scan internals. For key patterns and invariants, see the Architecture Notes section in `CLAUDE.md`.

## Scanner Pipeline

- `content_scanner.scan_all_files()` returns a 4-tuple: `(findings, bytes_scanned, files_skipped, suppressed_count)`
- Concurrent scanning uses `ProcessPoolExecutor` when file count >= `MIN_FILES_FOR_CONCURRENCY` (8); falls back to sequential on `OSError`/`RuntimeError`
- `ScanConfig.max_workers`: `0` = auto-detect (capped at 8), positive = explicit worker count (also capped at 8)
- `ScanResult.suppressed_count`: count of findings removed by inline `# noqa: RULE-ID` comments; default `0`
- `match_content()` in `engine.py` is a public wrapper with no `_depth` parameter; `_match_content_recursive()` is the private implementation that carries `_depth`
- `_line_phase_findings(content, file_path, line_rules)` — extracted helper that runs per-line matching and then the multi-line PI pass; called from `_match_content_recursive`
- `_multiline_pi_findings(content, file_path, pi_rules, existing)` — sliding window (sizes 3, 4, 5) that joins consecutive lines with a space and applies prompt-injection rules; only `category == 'prompt-injection'` rules are used; findings are attributed to the first line of the window; deduplicates against `existing` findings by `(rule_id, any_line_in_window)`; returns only NEW findings not already found by per-line scan
- `_scan_window_rule(rule, joined, file_path, first_line_num, window_line_nums, found_lines, results)` — extracted helper for checking one rule against one window; updates `found_lines` tracking on match

## AST Analyzer

- `analyze_python()` returns an `AST-PARSE` INFO finding on `SyntaxError`/`ValueError`/`RecursionError` during parsing; returns an `AST-DEPTH` INFO finding (plus any accumulated findings) on `RecursionError` during tree walking
- `AST-PARSE` and `AST-DEPTH` findings are exempt from `active_ids` filtering in `content_scanner._apply_rules()` — they always propagate to output
- `MAX_AST_RESOLVE_DEPTH = 50` in `_ast_helpers.py` — recursive string-resolution helpers return `None` instead of crashing at depth > 50
- `build_alias_map(tree)` in `_ast_helpers.py` returns `dict[str, str]` mapping local alias to canonical module name; called by `analyze_python()` and threaded to all `_detect_*` functions via `alias_map` kwarg; recurses into `ast.Try` blocks (body, handlers, orelse, finalbody) via `_collect_imports` / `_try_bodies` so imports inside `try/except` are captured; `from X import *` is expanded for known-dangerous modules via `_STAR_IMPORT_EXPANSIONS` (os, subprocess, shutil, socket)
- `get_call_name(node, alias_map=None)` resolves aliased call names (e.g. `c.encode` with `alias_map={'c': 'codecs'}` → `'codecs.encode'`); all `_detect_*` functions accept `alias_map` kwarg (empty-dict default, backward-compatible)
- `ast_analyzer.py` uses a `_DETECTORS` tuple to register all detector functions; current detectors: `_detect_unsafe_calls`, `_detect_dynamic_imports`, `_detect_unsafe_deserialization`, `_detect_string_concat_evasion`, `_detect_dynamic_access`, `_detect_decorator_evasion`, `_detect_rot13_codec`, `_detect_rot13_maketrans`, `_detect_subprocess_list_exfil`, `_detect_dns_exfil`; add new detectors to this tuple
- `analyze_python()` also calls `build_symbol_table(tree)`, `collect_loop_assigns(tree)` (merged into `symbol_table`), `_collect_int_list_assigns(tree)`, `detect_split_evasion(...)`, and `detect_kwargs_unpacking(...)` separately from the `_DETECTORS` loop — tree-level detectors that need the full symbol table go here, not in `_DETECTORS`; `_detect_custom_rot13` is called in a separate loop over `ast.FunctionDef | ast.AsyncFunctionDef` nodes

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

- `detect_split_evasion()` reconstructs strings via: `BinOp(Add)`, f-string interpolation, `"".join(...)`, `'template'.format(...)` (positional and keyword args), `'template'.format_map(dict)`, `'%s%s' % (a, b)`, `.replace()` chains, case-method chains (`.lower()`, `.upper()`, `.title()`, `.swapcase()`, `.capitalize()`, `.casefold()`), `functools.reduce()` concat, dict/list subscript lookups, `ast.Attribute` (`self.attr`), `ast.Call` (return values), `reversed()` join, `chr()`/`ord()` chains, bytes-constructor patterns including `bytes.fromhex()` inline concatenation, comprehension `chr()` mapping (including tracked int-list variables via `int_list_table` and nested 2-generator comprehensions), `map(lambda c: chr(c), [...])` (lambda-chr pattern), string reversal via `[::-1]` subscript slices, dynamic dispatch via introspection subscripts, and loop-assembled strings from `collect_loop_assigns` pre-pass (merged into symbol_table)
- Emits EXEC-002 for dangerous names (eval, exec, system, popen), EXEC-006 for dynamic import names (`__import__`, `getattr`); also bridges to decoder for split encoded payloads
- `_RESOLVERS` — tuple of `(predicate, resolver)` pairs registered in `_ast_split_detector.py`; current order: `_is_binop_add`, `_is_binop_mod`, `_is_fstr`, `_is_replace`, `_is_case`, `_is_subscript`, `_is_call`; `_try_resolve_split()` iterates and returns first non-`None` result; all resolvers share signature `(node, symbol_table, scope, *, alias_map=None) -> str | None`; add new resolvers here; `_is_subscript` (added in PLAN-030) resolves `ast.Subscript` nodes including `[::-1]` string reversal
- `_NAME_RULE` maps dangerous names to `(rule_id, severity, description_prefix)`
- `_DECORATOR_RULE` in `_ast_detectors.py` mirrors `_NAME_RULE` locally to avoid import cycle

## Split-Evasion Sub-modules

- `_ast_split_resolve.py` — expression resolution helpers (`resolve_binop_chain`, `resolve_operand`, `resolve_fstring`, `resolve_expr`, `resolve_call_return`, `resolve_call`); includes `_resolve_format_map_call` for `str.format_map(dict)` resolution; re-exports from `_ast_split_bytes`, `_ast_split_reduce`, `_ast_split_helpers`; at 285/300 lines — limited room
- `resolve_expr()` — resolves `ast.Name`, `ast.Attribute`, `ast.Subscript`, `ast.Call`; Attribute resolution gated to `self`/`cls`.attr and `ClassName.attr` only
- `resolve_call_return()` — resolves calls via parentheses-suffix composite key; handles `func()` and `self.method()` / `ClassName.method()`
- `resolve_call()` — registry-compatible wrapper chaining join, format, bytes-constructor, reduce, and call-return resolvers
- `_resolve_replace_chain()` — walks `.replace()` chains up to 20 levels deep
- `_CASE_METHODS` frozenset + `_is_case_method()` + `_resolve_case_method_chain()` — resolves chained `.lower()`, `.upper()`, `.title()`, `.swapcase()`, `.capitalize()`, `.casefold()` calls (no args) up to 20 levels deep; resolves base via `_resolve_base_string` (constant or symbol-table lookup) then falls back to `resolve_expr`; registered in `_RESOLVERS` before `_is_call`; follows the `_replace` pattern
- `_ast_split_chr.py` — resolves `chr(N)`, `chr(ord('x'))`, `chr(ord('x') + N)`; `_MAX_INT_DEPTH = 50`
- `_ast_split_bytes.py` — resolves `bytearray(b'...').decode()`, `str(b'...', 'utf-8')`, `codecs.decode(b'...', 'utf-8')`; also resolves inline `(bytes.fromhex('XX') + bytes.fromhex('YY')).decode()` via `resolve_fromhex_concat`; `_build_bytes_table` pre-pass tracks `name = bytes.fromhex(...)` variable assignments for split-evasion; gates on literal bytes arguments only; symbol_table is `dict[str, str]` and cannot hold bytes objects — tracked-variable fromhex is limited to the pre-pass
- `_ast_split_reduce.py` — resolves `functools.reduce(lambda a,b: a+b, [...])` and `functools.reduce(operator.add/concat, [...])`
- `_ast_split_helpers.py` — format/%-format resolution; `_scoped_lookup`, `_resolve_join_elements`, `_resolve_subscript_expr`, `_resolve_slice_expr`; `_PERCENT_SPEC_RE` matches all standard %-specifiers with `(?<!%)` lookbehind; `_resolve_format_call` handles both positional and keyword args (keyword args via `node.keywords` loop, rejecting `**kwargs` spreads where `kw.arg is None`); `_resolve_slice_expr` handles `step == -1` reversal (rejects only `step == 0`); at 297/300 lines — near limit
- `_ast_split_join_helpers.py` — `_resolve_join_call()` dispatches to list/tuple, comprehension, reversed, or map resolvers; passes `int_list_table` and `int_list_scope` to `_resolve_map_join`; `_collect_int_list_assigns(tree)` pre-pass collects `Name = [int, ...]` assignments AND tracks `+=`/`.extend()` mutations (module/function/class-method scope) as `dict[str, list[int]]`; delegates statement dispatch to `_handle_int_list_stmt` from `_ast_split_int_list_helpers`; `_resolve_comprehension_join()` accepts `int_list_table` kwarg and resolves `chr(c) for c in tracked_var` via `_resolve_tracked_iter()`; also resolves nested 2-generator comprehensions of the form `[chr(c) for row in [[ints],[ints]] for c in row]` by flattening the 2D list-of-lists before dispatching to `_resolve_comprehension_chr`; at 298/300 lines
- `_ast_split_int_list_helpers.py` — int-list mutation tracking helpers extracted from `_ast_split_join_helpers`; exposes `_SHADOW` sentinel and `_handle_int_list_stmt(stmt, scope, result)` dispatch entry point; `_handle_assign` tracks `Name = [int, ...]` (stores `_SHADOW` for non-int-list values); `_handle_extend_call` handles `name.extend([...])` calls; `_extend_tracked` handles both `+=` and `.extend()` mutations — ignores unknown variables, converts to `_SHADOW` on mixed-type or non-literal arg, concatenates on all-int literal; `_extract_int_list(elts)` returns `list[int] | None`; identity check `existing is _SHADOW` distinguishes shadow markers from legitimate empty lists
- `_ast_split_map_helpers.py` — `_resolve_map_join(call, sep, alias_map, *, int_list_table, int_list_scope)` handles `map(chr, [ints])`, `map(lambda c: chr(c), [ints])`, and `map(str, [strs])`; `_effective_map_fn(func_arg, alias_map)` normalizes both `ast.Name` references and `ast.Lambda` (`lambda c: chr(c)`) to a canonical function name; `_is_lambda_chr(node)` validates lambda structure (single arg, body is `chr(arg)`, no vararg/kwonly); tracked int-list variables resolved via `_resolve_tracked_elts`

## Dynamic Dispatch Detection

- `_check_dynamic_dispatch()` detects `globals()['eval']`, `vars(obj)['eval']`, `obj.__dict__['eval']`, and two-level chaining
- `_INTROSPECTION_FUNCS = frozenset({"vars", "globals", "locals"})`
- `_is_introspection_base()` checks `ast.Call` to introspection func or `ast.Attribute` with `attr == '__dict__'`
- `_extract_subscript_key()` resolves subscript key from `ast.Constant` or `ast.Name` via `_scoped_lookup`

## Kwargs Unpacking Detector

- `detect_kwargs_unpacking()` detects dangerous keyword arguments via `**` unpacking (e.g. `subprocess.run(**opts)` where `opts={'shell': True}`)
- `_DANGEROUS_KWARGS` — table-driven config mapping function-name prefixes to `(kwarg_key, kwarg_value, rule_id, severity, description_prefix)` tuples; extend by adding entries
- Dict-collection functions live in `_ast_kwargs_dict_tracker.py` (extracted from `_ast_kwargs_detector.py` to stay under 300 lines); all symbols are re-exported from `_ast_kwargs_detector.py` for backward compatibility
- `_collect_dict_assigns(tree)` in `_ast_kwargs_dict_tracker.py` — pre-pass collecting dict assignments from module, function, and class-method scope; stores raw Python constant values (preserving native types via `_eval_constant_expr`); handles dict union operators (`|`, `|=`) via `_track_union` / `_track_aug_union`, and `.update()` calls via `_handle_update_call`; unresolvable operands drop the variable conservatively
- `_handle_update_call(call, result, scope)` — tracks `opts.update({'shell': True})`; resolves the single positional dict arg (literal or tracked variable) and merges into existing tracked dict; silently skips keyword-only args and unresolvable arguments; creates new entry if variable not yet tracked
- `_eval_constant_expr(node)` — resolves `ast.Constant` or `ast.UnaryOp(USub|UAdd, Constant)` to a Python value; returns `_UNRESOLVABLE` sentinel on failure; handles negative int/float literals (e.g. `shell=-1`)
- `_extract_dict_literal(node)` — returns `dict[str, object]` with raw Python constant values (not `str()`); returns `None` if any `**spread` is present
- `_resolve_dict_operand(node, result, scope)` — resolves a dict union operand; recurses into `ast.BinOp(BitOr)` for chained unions (`a | b | c`); returns `None` conservatively if any operand is unresolvable
- `_kwarg_matches(resolved, key, value)` — uses Python native truthiness for `bool` table entries (`bool(resolved_val) == value`), allowing `shell=1` and `shell='0'` to match correctly; falls back to `str()` equality for non-bool table entries; `_FALSY_STRINGS` is removed

## Exfil Detector

- `_ast_exfil_detector.py` — node-level detectors for data exfiltration patterns; registered in `_DETECTORS` in `ast_analyzer.py`; new module was created because `_ast_detectors.py` was at 294/300 lines
- `_detect_subprocess_list_exfil(node, file_path, *, alias_map)` — emits `EXFIL-008` when a `subprocess.run/call/check_output/check_call/Popen` call has a list as first arg whose first element is a network tool name; uses `get_call_name` for alias resolution; handles `/usr/bin/curl`-style paths via `split('/')[-1]`
- `_detect_dns_exfil(node, file_path, *, alias_map)` — emits `EXFIL-006` when `socket.getaddrinfo()` is called with a non-literal first argument (f-strings, variables, concatenation, or any non-`ast.Constant` node); literal string hostnames are safe and not flagged; uses `get_call_name` for alias resolution (catches star-import expanded `getaddrinfo`)
- `_SUBPROCESS_CALLS` — frozenset of recognized subprocess function names (qualified: `subprocess.run`, etc.)
- `_NETWORK_TOOLS` — frozenset of network tool names that trigger detection: `curl`, `wget`, `nc`, `ncat`, `netcat`
- `_DNS_EXFIL_TARGETS` — frozenset of DNS exfil function names: `socket.getaddrinfo`; extend by adding entries
- Uses `Finding()` directly with `category='data-exfiltration'` — do NOT use `_make_finding` (which hardcodes `'malicious-code'`)

## Decoder

- `decode_payload()` has two return paths: bytes→UTF-8 for `base64`/`hex`; direct `str` for `url`/`unicode_escape` (via `_decode_str_payload()`)
- `_decode_unicode_escape()` strips lone surrogates (U+D800–U+DFFF) to prevent surrogate-interspersed evasion
- `_decode_url_encoded()` strips null bytes (`\x00`) to prevent null-byte-interspersed evasion
- `EncodedPayload.encoding_type` accepts `'base64'` | `'hex'` | `'url'` | `'unicode_escape'`

## ROT13 Detection

- `_ast_rot13.py` uses its own `_make_rot13_finding()` with `category='obfuscation'` — do NOT reuse `_make_finding` from `_ast_detectors.py` which hardcodes `category='malicious-code'`
- `is_rot13_pair(from_str, to_str) -> bool` is a public pure function; re-exported from `ast_analyzer.py`
- `_detect_custom_rot13(func_node, file_path) -> list[Finding]` — heuristic detector for manual chr/ord ROT13 functions; called in a separate loop in `analyze_python()` over `ast.FunctionDef | ast.AsyncFunctionDef` nodes; requires BOTH a lowercase branch (contains `'a'` or `'z'` string constants) AND an uppercase branch (`'A'` or `'Z'`) AND `% 26` arithmetic AND `chr`/`ord` calls within the function body; emits OBFS-001; all four conditions are required to minimize false positives
- OBFS-001 in `obfuscation.toml` has `patterns = []` — detection is AST-only; the TOML entry exists for rule metadata (severity, description, recommendation) and catalog generation; do NOT add regex patterns

## Loop Unroller

- `_ast_loop_unroller.py` — pre-pass module for static resolution of for-loop string assembly patterns
- `collect_loop_assigns(tree: ast.Module) -> dict[str, str]` — scans module-level and function-level bodies; returns a dict mapping `target_name` (or `funcname.target_name` for function scope) to the concatenated string value; called in `analyze_python()` and merged into `symbol_table` before `detect_split_evasion` runs
- Supported pattern: `target = ''` initialized before the loop, followed by `for VAR in [str, str, ...]: target += VAR`; iter must be an inline list literal or a `Name` referencing a local list-literal assignment; body must be exactly one `AugAssign` with `ast.Add`
- Returns `None` (skips) if: iter is not a recognized list source, body has multiple statements, body contains non-string elements, there is no `target = ''` initialization, or the body statement is not `target += loop_var`
- Only single-level loops supported — nested loops and loops with if-guards are not unrolled (conservative)
- Keys use the same scoping prefix as `build_symbol_table` (`"funcname.varname"`) so merged values are resolved by split-evasion correctly

## Known Limitations

- Return-value tracking: method returning via `self.attr` is NOT tracked (conservative gap); `_resolve_call_assignments` handles module-level `x = func()` only; only same-module calls resolved
- PEP 448 spread dicts (`{**base, 'shell': True}`) in kwargs unpacking are unresolvable by design (conservative; spread ordering can override extracted keys)
- `_collect_int_list_assigns` tracks only all-integer lists/tuples (conservative); mixed-type lists (`[101, 'x']`) and non-literal arguments to `+=` or `.extend()` convert the variable to `_SHADOW` (unresolvable)
- `_collect_int_list_assigns` does not walk class-level statements (only class methods); `class C: codes = [ints]; codes += [more]` at class body scope is untracked (DEBT-028-INTLIST-CLASS-BODY)
- `codes = a + b` (int-list concatenation via BinOp) is not tracked in the pre-pass; requires cross-variable resolution (DEBT-027-INTLIST-CONCAT)
- `codes.extend(a)` where `a` is a tracked variable (not a literal) is ignored conservatively (DEBT-027-INTLIST-EXTEND-VAR)
- `collect_loop_assigns` supports only inline string-literal lists and local list-literal name references as iter source; tracked list variables from `symbol_table` are NOT supported (`symbol_table` is `dict[str, str]`); int-list iter sources (e.g., `for c in int_codes`) are also unsupported via this pre-pass
- `resolve_fromhex_concat` handles only inline `(bytes.fromhex('XX') + bytes.fromhex('YY')).decode()` expressions — tracked-variable fromhex (e.g., `a = bytes.fromhex('6576'); b = bytes.fromhex('616c'); (a + b).decode()`) requires a separate bytes-tracking pre-pass (not yet implemented)
- Nested comprehension support is limited to exactly 2 generators with the inner iter being a plain `Name` matching the outer target variable; 3+ generators return `None`

## Evasion Corpus

Test fixtures at `tests/fixtures/split_evasion/` — positive (`pos_`) files should detect, negative (`neg_`) should not trigger. Corpus test filter uses `rule_id` matching (`f.rule_id in ('EXEC-002', 'EXEC-006')`). Format/%-format fixtures use `UP030`/`UP031`/`UP032` ruff ignores (intentional old-style syntax).
