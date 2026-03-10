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
- Core scanner engine and decoder use stdlib only (`re`, `pathlib`, `json`, `tomllib`, `base64`, `binascii`, `ast`, `concurrent.futures`)
- Don't add deps without `uv` + `pyproject.toml`
- **Max 250 lines per file** (source code in `src/` and `tests/`)
- `_ast_helpers.py` is at 246 lines (near limit) — any addition requires a split first

## Project Structure

```
src/skill_scan/           # Production source code
  ast_analyzer.py         # Facade: analyze_python() entry point + re-exports from _ast_detectors
  _ast_detectors.py       # Private detector functions (_detect_* and _make_finding)
  _ast_helpers.py         # Private string-resolution helpers for AST analysis
  decoder.py              # Facade: EncodedPayload, public constants, extract/decode + re-exports
  _decoder_helpers.py     # Private regex constants and extraction/decode helpers
  content_scanner.py      # File I/O + rule dispatch + AST deduplication + concurrent scanning
  suppression.py          # Inline noqa suppression (public: parse_noqa, filter_suppressed)
tests/                    # Test suite (mirrors src/ structure)
scripts/                  # Quality & analysis scripts
.agent/                   # Plans, standards, workflow
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
- `ast_analyzer.py` and `decoder.py` are facade modules — they re-export all names from their sibling `_ast_detectors.py` and `_decoder_helpers.py` respectively (Facade Re-export Pattern)

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
