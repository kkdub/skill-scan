# PLAN-001 Review Findings

Post-implementation findings from architecture and security reviews (2026-02-15).
All items are non-blocking — MVP is complete and functional.

---

## Security Findings

### [HIGH] Symlink following in file scanner — FIXED

- **File:** `src/skill_scan/scanner.py` `_collect_files()`
- **Status:** Fixed
- **Fix applied:** Added `is_symlink()` check and `is_relative_to()` boundary check

### [MEDIUM] No regex compilation error handling — FIXED

- **File:** `src/skill_scan/rules/loader.py` (`_compile_patterns`)
- **Status:** Fixed
- **Fix applied:** Wrapped `re.compile()` in try/except, raises `ValueError` with
  pattern context on `re.error`. Test added in `test_rules_loader.py`.

### [MEDIUM] No per-pattern regex timeout — DEFERRED

- **File:** `src/skill_scan/rules/engine.py` (`match_line`)
- **Status:** Deferred (stdlib limitation)
- **Risk:** No defense-in-depth against ReDoS from future rule patterns. Current
  PI-001 through PI-006 patterns are safe (tested), but new rules could introduce
  vulnerable patterns. The `max_file_size` limit (500KB) bounds input but a single
  long line matched against a vulnerable regex could still hang.
- **Note:** Python stdlib `re` module does not support a `timeout` parameter on
  `re.compile()` or `re.search()`. Would require the third-party `regex` package,
  which conflicts with the stdlib-only constraint. Current mitigations (bounded
  input via `max_file_size`, vetted built-in patterns) are sufficient for MVP.

### [LOW] Unsanitized user content in error messages — FIXED

- **File:** `src/skill_scan/parser.py` (`_parse_fields`)
- **Status:** Fixed
- **Fix applied:** Used `!r` (repr) formatting with `[:100]` truncation to escape
  control characters in error messages from untrusted SKILL.md content.

### [LOW] Path disclosure in error messages

- **Files:** `src/skill_scan/parser.py:38`, `src/skill_scan/_fetchers.py:47,49`
- **Status:** Accepted (CLI-only tool)
- **Risk:** Full filesystem paths in error messages. Fine for CLI, would need
  sanitization if the tool is ever wrapped in a web API.

### [LOW] `.env.example` placeholder resembles real token — FIXED

- **File:** `.env.example:4`
- **Status:** Fixed
- **Fix applied:** Changed `ghp_your_token_here` to `<your-token>` to avoid
  triggering automated secret scanners.

---

## Architecture Findings

### [WARNING] Dead `main.py` placeholder — FIXED

- **File:** `main.py`
- **Status:** Fixed
- **Fix applied:** Deleted `main.py`. The real entry point is
  `skill_scan.cli:skill_scan` (registered in pyproject.toml).

### [WARNING] `scanner.py` hardcodes LocalFetcher — FIXED

- **File:** `src/skill_scan/scanner.py`
- **Status:** Fixed
- **Fix applied:** Added optional `fetcher: SkillFetcher | None = None` parameter
  to `scan()`. Defaults to `LocalFetcher()` when not provided, preserving backward
  compatibility while enabling dependency injection for testing and future fetchers.

### [WARNING] `Rule` not exported from public API — FIXED

- **File:** `src/skill_scan/__init__.py`
- **Status:** Fixed
- **Fix applied:** Added `Rule` to `__all__` and the import statement.
  Test updated in `test_formatters.py::TestPublicAPIImports`.

### [SUGGESTION] Swallowed SkillParseError message — FIXED

- **File:** `src/skill_scan/scanner.py`, `src/skill_scan/models.py`
- **Status:** Fixed
- **Fix applied:** Added `error_message: str | None = None` field to `ScanResult`.
  The `scan()` function now captures `str(e)` from `SkillParseError` and passes it
  to the result. The text formatter displays it as a "Detail:" line when present.
  Tests added in `test_scanner.py`, `test_models.py`, and `test_formatters.py`.

### [SUGGESTION] `runtime_checkable` on SkillFetcher — KEPT

- **File:** `src/skill_scan/_fetchers.py:13`
- **Status:** Kept (intentional)
- **Reason:** `test_fetchers.py::test_local_fetcher_is_skill_fetcher_protocol` uses
  `isinstance(fetcher, SkillFetcher)` to verify protocol compliance. The decorator
  is needed for this test.

---

## Pre-existing Issues (not from this plan)

### `check-code-patterns` pre-commit hook path

- **File:** `.pre-commit-config.yaml`
- **Status:** Already resolved
- **Note:** The script at `scripts/check_code_patterns.py` references
  `.agent/standards/code-rules.json` (singular), which matches the current
  project structure after the `.agents/` to `.agent/` migration.
