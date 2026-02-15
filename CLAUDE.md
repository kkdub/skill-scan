# skill-scan

Security scanner for agent skills — detect prompt injection, malicious code, and data exfiltration before installation.

## Quick Reference

- **Plans & specs**: `.agents/plans/`
- **Code patterns and rules**: `.agents/standards/`
- **Workflow context**: `.agents/WORKFLOW.md`

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

- Follow `.agents/standards/CODE-PATTERNS.md` for design decisions
- Follow `.agents/standards/TEST-PATTERNS.md` when writing or modifying tests
- Rules enforced via `.agents/standards/code-rules.json`
- Type hints on all public functions
- Tests in `tests/`
- Core scanner engine uses stdlib only (`re`, `pathlib`, `json`, `tomllib`)
- Don't add deps without `uv` + `pyproject.toml`
- **Max 250 lines per file** (source code in `src/` and `tests/`)

## Project Structure

```
src/skill_scan/     # Production source code
tests/              # Test suite (mirrors src/ structure)
scripts/            # Quality & analysis scripts
.agents/            # Plans, standards, workflow
```

## Tips

- Uncertainty is fine — flag what you find, suggest improvements.
- Keep files small and focused. Split early, split often.
