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
- **Max 250 lines per file** (source code in `src/` and `tests/`)

## Project Structure

```
src/skill_scan/           # Production source code
  ast_analyzer.py         # Facade: analyze_python() entry point + re-exports from _ast_detectors + _ast_rot13 + _ast_symbol_table + _ast_split_detector
  _ast_detectors.py       # Private detector functions (_detect_* and _make_finding)
  _ast_helpers.py         # Private string-resolution helpers + build_alias_map + get_call_name; re-exports from _ast_join_helpers
  _ast_join_helpers.py    # Private join-resolution helpers extracted from _ast_helpers
  _ast_rot13.py           # ROT13 AST detectors (is_rot13_pair, _detect_rot13_codec, _detect_rot13_maketrans)
  _ast_symbol_table.py    # Symbol table builder (build_symbol_table); pre-pass variable-to-string mapping with scope isolation
  _ast_split_detector.py  # Split-evasion detector (detect_split_evasion); reconstructs concat/f-string/join payloads
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
- `ast_analyzer.py` and `decoder.py` are facade modules — they re-export all names from their sibling `_ast_detectors.py`/`_ast_rot13.py`/`_ast_symbol_table.py`/`_ast_split_detector.py` and `_decoder_helpers.py`/`_decoder_url_unicode.py` respectively (Facade Re-export Pattern)
- `build_alias_map(tree)` in `_ast_helpers.py` returns `dict[str, str]` mapping local alias to canonical module name; called by `analyze_python()` and threaded to all `_detect_*` functions via `alias_map` kwarg
- `get_call_name(node, alias_map=None)` resolves aliased call names (e.g. `c.encode` with `alias_map={'c': 'codecs'}` → `'codecs.encode'`); all `_detect_*` functions accept `alias_map` kwarg (empty-dict default, backward-compatible)
- `ast_analyzer.py` uses a `_DETECTORS` tuple to register all detector functions; add new detectors to this tuple
- `analyze_python()` also calls `build_symbol_table(tree)` and `detect_split_evasion(tree, file_path, alias_map, symbol_table)` separately from the `_DETECTORS` loop — tree-level detectors that need the full symbol table go here, not in `_DETECTORS`
- `build_symbol_table(tree: ast.Module) -> dict[str, str]` in `_ast_symbol_table.py` — pre-pass that returns a flat dict of variable-to-string mappings; function-scoped variables are prefixed `"funcname.varname"`; bounded by `MAX_RESOLVE_DEPTH = 50`; circular references are dropped silently
- `detect_split_evasion(tree, file_path, alias_map, symbol_table) -> list[Finding]` in `_ast_split_detector.py` — reconstructs strings assembled via `BinOp(Add)`, f-string interpolation, or `"".join(...)` using the symbol table; emits EXEC-002 for dangerous names (eval, exec, system, popen), EXEC-006 for dynamic import names (`__import__`, `getattr`); also bridges to decoder for split encoded payloads
- `_NAME_RULE` in `_ast_split_detector.py` is a lookup table mapping each dangerous name to `(rule_id, severity, description_prefix)` — use this pattern when one detector must emit different rule IDs per matched name
- `_Ref` sentinel class in `_ast_symbol_table.py` marks unresolved variable references during the pre-pass; resolved to `str` or dropped before `build_symbol_table()` returns
- Evasion corpus at `tests/fixtures/split_evasion/` — 17 positive (should detect) and 4 negative (should not trigger) Python fixture files; prefix `pos_` / `neg_`
- `decode_payload()` in `decoder.py` has two return paths: bytes→UTF-8 for `base64`/`hex`; direct `str` for `url`/`unicode_escape` (via `_decode_str_payload()`)
- `EncodedPayload.encoding_type` accepts `'base64'` | `'hex'` | `'url'` | `'unicode_escape'`
- OBFS-* is the rule namespace for obfuscation detection (distinct from EXEC-* for malicious code execution); OBFS-001 is AST-based (ROT13), OBFS-002..005 are regex-based in `obfuscation.toml`
- `_ast_rot13.py` uses its own `_make_rot13_finding()` with `category='obfuscation'` — do NOT reuse `_make_finding` from `_ast_detectors.py` which hardcodes `category='malicious-code'`
- `is_rot13_pair(from_str, to_str) -> bool` in `_ast_rot13.py` is a public pure function; re-exported from `ast_analyzer.py`

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
