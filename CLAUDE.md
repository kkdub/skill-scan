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
- Core scanner engine and decoder use stdlib only (`re`, `pathlib`, `json`, `tomllib`, `base64`, `binascii`, `ast`)
- Don't add deps without `uv` + `pyproject.toml`
- **Max 250 lines per file** (source code in `src/` and `tests/`)
- `ast_analyzer.py` is at exactly 250 lines — any addition requires a split first

## Project Structure

```
src/skill_scan/           # Production source code
  ast_analyzer.py         # AST-based analysis for Python files (public: analyze_python)
  _ast_helpers.py         # Private string-resolution helpers for AST analysis
  content_scanner.py      # File I/O + rule dispatch + AST deduplication
tests/                    # Test suite (mirrors src/ structure)
scripts/                  # Quality & analysis scripts
.agent/                   # Plans, standards, workflow
```

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
