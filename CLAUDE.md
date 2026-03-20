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
- **Max 300 lines per file** (source code in `src/` and `tests/`)

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
  _ast_split_comprehension.py # Generator/comprehension join resolution; _collect_int_list_assigns pre-pass
  _ast_split_int_list_tracker.py # Int-list mutation tracking (_SHADOW sentinel, _handle_int_list_stmt, _handle_assign, _handle_extend_call, _extend_tracked)
  _ast_split_map_resolver.py # map(chr/str/lambda, [...]) resolution for join patterns
  _ast_split_star_unpack.py  # Star-unpack flattening for join arguments (_flatten_starred_list, _expand_starred, _maybe_flatten_starred)
  _ast_kwargs_detector.py # Kwargs unpacking detector (detect_kwargs_unpacking); re-exports from _ast_kwargs_dict_tracker.py
  _ast_kwargs_dict_tracker.py # Dict-collection pre-pass + .update() tracking; _build_string_table for dynamic key resolution
  _ast_exfil_detector.py  # Subprocess list-arg + DNS exfil detectors (_detect_subprocess_list_exfil, _detect_dns_exfil)
  _ast_loop_unroller.py   # Static for-loop unrolling pre-pass (collect_loop_assigns)
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
    test_ast_split_int_list_tracker.py  # Int-list concat, extend-var, class-body pre-pass tests (PLAN-032 Part A)
    test_ast_kwargs_dict_tracker.py     # Dynamic key resolution tests (PLAN-032 Part B)
    test_ast_split_star_unpack.py       # Star-unpack flattening tests (PLAN-032 Part C)
    test_part_d_classvar_dictpop.py     # Class-body scope, classvar assembly, dict.pop tests (PLAN-032 Part D)
    test_hex_escape_resolution.py       # Hex escape .replace() chain + fromhex(var) tests (PLAN-032 Part E)
    ...                                 # Other tests mirror src/ structure
scripts/                  # Quality & analysis scripts
.agent/                   # Plans, standards, workflow
```

## Architecture Notes

Key patterns and invariants. For detailed module-level docs, see `.agent/ARCHITECTURE-REFERENCE.md`.

**Facade Re-export Pattern**: `ast_analyzer.py` and `decoder.py` are facade modules — they re-export from private siblings. Import public names from the facade, not the `_` modules.

**Registration patterns** — follow these when adding new detectors:
- `_DETECTORS` tuple in `ast_analyzer.py` — node-level detectors (one finding per node)
- `_RESOLVERS` tuple in `_ast_split_detector.py` — string resolvers for split-evasion; signature: `(node, symbol_table, scope, *, alias_map=None) -> str | None`
- Tree-level detectors needing the full symbol table (`detect_split_evasion`, `detect_kwargs_unpacking`) go in `analyze_python()` directly, not in `_DETECTORS`; `_detect_custom_rot13` is walked separately over `ast.FunctionDef | ast.AsyncFunctionDef` nodes (requires full function body, not per-node dispatch)
- `_NAME_RULE` / `_DECORATOR_RULE` — lookup tables mapping dangerous names to `(rule_id, severity, prefix)`; use when one detector emits different rule IDs per name
- `_DANGEROUS_KWARGS` — table-driven config for kwargs detector; extend by adding entries, no code changes needed
- `_collect_int_list_assigns(tree)` in `_ast_split_comprehension.py` — parallel pre-pass collecting `Name = [int, ...]` assignments AND tracking `+=`/`.extend()` mutations; built in `analyze_python()` and threaded to `detect_split_evasion` via `int_list_table` kwarg; mutation helpers live in `_ast_split_int_list_tracker.py`; also walks ClassDef body directly (class-level int-lists tracked under `ClassName.varname` key)
- `_handle_string_list_literal` in `_ast_symbol_table_dict_tracker.py` — tracks `name = ['ev', 'al']` assignments as indexed elements `name[0]`, `name[1]`, etc. and `name.__len__` in the symbol table; enables `parts[0] + parts[1]` BinOp resolution and star-unpack flattening
- `_handle_dict_literal` in `_ast_symbol_table_dict_tracker.py` — tracks `name = {'key': 'val'}` assignments as composite keys `name[key]` in the symbol table; enables dict.pop() resolution
- `_handle_dict_pop` in `_ast_symbol_table_dict_tracker.py` — resolves `target = d.pop('key')` by looking up `d[key]` in the symbol table composite key entries; called first in `_process_stmt` before `_handle_assign`
- `_resolve_replace_chain_simple` in `_ast_symbol_table_dict_tracker.py` — resolves chained `.replace(old, new)` on a constant or tracked variable in the symbol table builder; used to track hex strings with escape-sequence separators
- `_maybe_flatten_starred` in `_ast_split_star_unpack.py` — expands `ast.Starred` elements in join argument lists by looking up `name.__len__` and `name[i]` entries in the symbol table; called from `_resolve_join_call` before `_resolve_join_elements`
- `_build_string_table(body)` in `_ast_kwargs_dict_tracker.py` — local pre-pass that tracks `name = 'literal'` and `name = 'a' + 'b'` string assignments within a body; passed to `_extract_dict_literal` for Name key resolution in kwargs dict tracking
- `_CASE_METHODS` frozenset + `_is_case_method` / `_resolve_case_method_chain` in `_ast_split_method_chains.py` — resolves `.lower()`, `.upper()`, `.title()`, `.swapcase()`, `.capitalize()`, `.casefold()` chains; registered in `_RESOLVERS` before `_is_call` (follows `_is_replace_call` / `_resolve_replace_chain` pattern)
- `_SUBPROCESS_CALLS` / `_NETWORK_TOOLS` in `_ast_exfil_detector.py` — frozensets defining which subprocess variants and tool names trigger EXFIL-008; extend by adding entries, no code changes needed
- `_DNS_EXFIL_TARGETS` in `_ast_exfil_detector.py` — frozenset defining which calls trigger EXFIL-006 DNS exfil detection (`socket.getaddrinfo`); non-literal first arg triggers finding; extend by adding entries
- `_STAR_IMPORT_EXPANSIONS` dict in `_ast_imports.py` — allowlist mapping dangerous modules to their dangerous exports; `from os import *` expands to `os.system`, `os.popen`, etc. in `alias_map`; extend by adding module entries
- `collect_loop_assigns(tree)` in `_ast_loop_unroller.py` — pre-pass that resolves `for c in ['e','v','a','l']: name += c` patterns; called in `analyze_python()` and merged into `symbol_table` before `detect_split_evasion` runs; supports inline list literals and local list-literal name references; single-level loops with one AugAssign body only
- `_handle_update_call` in `_ast_kwargs_dict_tracker.py` — handles `dict.update({...})` in the kwargs pre-pass; follows same pattern as `_track_aug_union`
- `_try_bodies(node)` in `_ast_imports.py` — returns all body lists from a `Try` node (body, handlers, orelse, finalbody); used by `_collect_imports` to recurse into `try/except` blocks

**Invariants**:
- `normalize_text()` in `normalizer.py` applies NFKC normalization (`unicodedata.normalize('NFKC', text)`) as its FIRST step — this decomposes fullwidth Unicode characters (U+FF41-FF5A) and other compatibility characters before zero-width stripping and whitespace canonicalization
- `_handle_assign` in `_ast_symbol_table_assignments.py` iterates ALL targets in `stmt.targets` — multi-target assignments (`a = b = 'eval'`) track every target name with the same resolved value
- Bare `# noqa` does NOT suppress — security scanner requires explicit rule IDs (`# noqa: RULE-ID`)
- `AST-PARSE` and `AST-DEPTH` findings are exempt from `active_ids` filtering — always propagate
- `MAX_AST_RESOLVE_DEPTH = 50` — recursive helpers return `None` at depth > 50
- OBFS-* = obfuscation rules; EXEC-* = malicious code execution rules (distinct namespaces)
- `_make_rot13_finding()` uses `category='obfuscation'` — do NOT reuse `_make_finding` (hardcodes `'malicious-code'`)
- Deferred imports in `_ast_symbol_table.py` break circular deps — don't reorganize without checking import chains
- `_extract_dict_literal` returns `dict[str, object]` (raw Python constants, not `str()`); `_kwarg_matches` uses native Python truthiness for `bool` table entries and `str()` equality for non-bool entries — `int(0)` is falsy, `str("0")` is truthy
- `_eval_constant_expr` in `_ast_kwargs_dict_tracker.py` resolves `ast.Constant` and `ast.UnaryOp(USub|UAdd, Constant)` to Python values (handles negative int/float literals); returns `_UNRESOLVABLE` sentinel on failure; re-exported from `_ast_kwargs_detector.py`
- `_SHADOW` in `_ast_split_int_list_tracker.py` is a module-level sentinel `list[int]` that marks shadowed (non-int-list) variables in the int-list pre-pass; always compare by identity (`existing is _SHADOW`), never by equality — a legitimate empty list (`codes = []`) must not be confused with a shadow marker
- `build_alias_map(tree)` recurses into `ast.Try` blocks via `_collect_imports` → `_try_bodies` — imports inside `try/except/else/finally` are captured; do not flatten `tree.body` iteration without preserving this recursion
- `_is_lambda_chr(node)` in `_ast_split_map_resolver.py` validates exactly: single positional arg, no vararg, no kwonly args, body is `chr(arg)` with matching param name — do not relax these checks without a test for the edge case
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
- OBFS-001 TOML entry has `patterns = []` — detection is AST-only via `_detect_rot13_codec`, `_detect_rot13_maketrans`, and `_detect_custom_rot13`; do not add regex patterns (AST handles this more accurately)

**Known debt**:
- PEP 448 spread dicts (`{**base, ...}`) in kwargs are conservatively treated as unresolvable (no tracking planned)
- `_ast_split_resolve.py` is at 217/300 lines — has headroom after format_map extraction to `_ast_split_format_map.py`
- `_ast_split_format.py` is at 299/300 lines — effectively frozen; any addition requires offsetting removal first
- `_ast_imports.py` is at 160/300 lines — has headroom after string-resolver extraction to `_ast_string_resolver.py`
- `_ast_rot13.py` is at 247/300 lines — has headroom after branch analysis extraction to `_ast_rot13_branch_analysis.py`
- `_ast_split_comprehension.py` is at 290/300 lines — 10 lines remaining
- `_ast_symbol_table_assignments.py` is at 288/300 lines — 12 lines remaining
- `_ast_split_star_unpack.py` is at ~79/300 lines — ample room
- `_ast_symbol_table_dict_tracker.py` is at ~149/300 lines — ample room
- `collect_loop_assigns` supports only inline string-literal lists and local list-literal name references as iter source — tracked list variables from symbol_table are NOT supported (symbol_table is `dict[str, str]`, cannot hold lists)
- `_maybe_flatten_starred` in `_ast_split_star_unpack.py` only expands `ast.Starred` where the starred value is a plain `ast.Name` — starred expressions (computed, attribute, subscript) are not supported

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
