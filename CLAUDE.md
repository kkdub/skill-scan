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
  _ast_helpers.py         # String-resolution helpers + build_alias_map + get_call_name
  _ast_join_helpers.py    # Join-resolution helpers
  _ast_rot13.py           # ROT13 AST detectors
  _ast_symbol_table.py    # Symbol table builder (build_symbol_table)
  _ast_symbol_table_helpers.py       # Assignment-tracking helpers
  _ast_symbol_table_class_helpers.py # Class-attribute helpers (self.attr tracking)
  _ast_symbol_table_return_helpers.py # Return-value extraction
  _ast_split_detector.py  # Split-evasion detector (detect_split_evasion)
  _ast_split_helpers.py   # Format/%-format resolution helpers
  _ast_split_resolve.py   # Expression resolution helpers
  _ast_split_bytes.py     # Bytes-constructor resolution
  _ast_split_chr.py       # chr/ord/int resolution
  _ast_split_reduce.py    # reduce/operator concat resolution
  _ast_split_join_helpers.py # Generator/map/comprehension join resolution
  _ast_kwargs_detector.py # Kwargs unpacking detector (detect_kwargs_unpacking)
  decoder.py              # Facade: EncodedPayload, extract/decode
  _decoder_helpers.py     # Base64/hex extraction and decode
  _decoder_url_unicode.py # URL/unicode-escape extraction and decode
  content_scanner.py      # File I/O + rule dispatch + concurrent scanning
  suppression.py          # Inline noqa suppression
  rules/data/
    obfuscation.toml      # OBFS-002..005 regex-based rules
tests/                    # Test suite (mirrors src/ structure)
scripts/                  # Quality & analysis scripts
.agent/                   # Plans, standards, workflow
```

## Architecture Notes

Key patterns and invariants. For detailed module-level docs, see `.agent/ARCHITECTURE-REFERENCE.md`.

**Facade Re-export Pattern**: `ast_analyzer.py` and `decoder.py` are facade modules — they re-export from private siblings. Import public names from the facade, not the `_` modules.

**Registration patterns** — follow these when adding new detectors:
- `_DETECTORS` tuple in `ast_analyzer.py` — node-level detectors (one finding per node)
- `_RESOLVERS` tuple in `_ast_split_detector.py` — string resolvers for split-evasion; signature: `(node, symbol_table, scope, *, alias_map=None) -> str | None`
- Tree-level detectors needing the full symbol table (`detect_split_evasion`, `detect_kwargs_unpacking`) go in `analyze_python()` directly, not in `_DETECTORS`
- `_NAME_RULE` / `_DECORATOR_RULE` — lookup tables mapping dangerous names to `(rule_id, severity, prefix)`; use when one detector emits different rule IDs per name
- `_DANGEROUS_KWARGS` — table-driven config for kwargs detector; extend by adding entries, no code changes needed

**Invariants**:
- Bare `# noqa` does NOT suppress — security scanner requires explicit rule IDs (`# noqa: RULE-ID`)
- `AST-PARSE` and `AST-DEPTH` findings are exempt from `active_ids` filtering — always propagate
- `MAX_AST_RESOLVE_DEPTH = 50` — recursive helpers return `None` at depth > 50
- OBFS-* = obfuscation rules; EXEC-* = malicious code execution rules (distinct namespaces)
- `_make_rot13_finding()` uses `category='obfuscation'` — do NOT reuse `_make_finding` (hardcodes `'malicious-code'`)
- Deferred imports in `_ast_symbol_table.py` break circular deps — don't reorganize without checking import chains

**Known debt**:
- DEBT-025-DICT-UNION — dict union operator (`opts | {'shell': True}`, `opts |= {'shell': True}`) not handled by kwargs detector; PEP 448 spread dicts (`{**base, ...}`) are conservatively treated as unresolvable
- DEBT-024-TRACKED-COMPREHENSION — tracked variable as comprehension iterable needs symbol table extension for non-string values

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
