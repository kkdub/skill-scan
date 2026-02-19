# PLAN-010 Test Suite Cleanup
## STATUS: COMPLETE
## Context

After significant refactoring (splitting scanner.py into file_collector.py, file_classifier.py, file_checks.py, content_scanner.py), the test suite was left as-is. An audit of all 1706 tests against TEST-PATTERNS.md and test-rules.json revealed:

- **14 fully redundant tests** (mostly in test_bypass_coverage.py — 7 of 14)
- **9 weak assertions** that don't catch regressions
- **1 systemic DRY violation** (helper copy-pasted into 9+ files)
- **4 misplaced test classes/functions**
- **2 tests to delete** for being tautological

This plan addresses all findings in priority order across 4 parts.

## Part 1: Delete Redundant Tests

Remove 14 tests that are fully covered elsewhere. No behavioral coverage is lost.

### Files to modify

**tests/unit/test_bypass_coverage.py** — Delete 7 tests:
- `test_scan_unknown_ext_finding_has_correct_severity` (line 37) — covered by test_file_checks.py:47
- `test_scan_binary_not_content_scanned` (line 62) — covered by test_scanner_file_safety.py:13
- `test_scan_binary_triggers_degraded_reasons` (line 72) — covered by test_observability.py:64
- `test_scan_oversized_finding_severity` (line 99) — covered by test_file_checks.py:89
- `test_scan_decode_error_populates_degraded_reasons` (line 140) — covered by test_observability.py:25
- `test_scan_binary_skip_populates_degraded_reasons` (line 149) — covered by test_observability.py:64
- `test_scan_no_degradation_empty_reasons` (line 157) — covered by test_scanner.py:226

Also delete the now-empty `TestDegradedReasons` class (all 3 methods removed). The `TestVerdictUpgradeOnDegradation` class survives (line 166) — its `test_scan_degraded_upgrades_pass_to_flag` and `test_scan_degraded_with_findings_keeps_higher_verdict` are unique.

**tests/unit/test_scanner.py** — Delete 1 test:
- `test_scan_counts_binary_files_as_skipped` (line 217) — subset of `test_scan_with_binary_file_tracks_as_skipped` (line 235) which also asserts verdict

**tests/unit/test_scanner_file_safety.py** — Delete 1 test:
- `test_scan_fs001_is_medium_severity` (line 112) — severity already asserted at line 53 in same file

**tests/unit/test_github_fetcher_errors.py** — Delete 1 test:
- `test_cleanup_on_failure` (line 59) — identical mock+assertion as `test_404_raises_fetch_error` (line 28)

**tests/unit/test_config.py** — Delete 1 test:
- `test_load_config_returns_scan_config` (line 51) — `isinstance` check trivially true; subsumed by every other config test

**tests/unit/test_json_formatter.py** — Delete 1 test:
- `test_same_input_produces_identical_output` (line 214) — tautology (pure function on frozen dataclass)

**tests/integration/test_cli_repo.py** — Delete 1 class:
- `TestLocalScanStillWorks` (line 77) — duplicates test_cli.py:19 + :27

**tests/unit/test_bypass_coverage.py** — Delete 1 more:
- `test_scan_no_degradation_clean_passes` in `TestVerdictUpgradeOnDegradation` (line 180) — covered by test_scanner.py:226

### Verification
- `make check` passes
- Test count drops by ~14
- No coverage gap (every deleted test has a named survivor)

## Part 2: Consolidate Rule Test Helpers (DRY)

Extract duplicated `_match`/`_findings` helpers from 9+ files into `tests/unit/rule_helpers.py`.

### Add to rule_helpers.py

```python
def match_rule(line: str, rules: list[Rule], rule_id: str) -> bool:
    """Check if a rule matches a line. Returns True/False."""
    return any(f.rule_id == rule_id for f in match_line(line, 1, "test.md", rules))

def rule_findings(line: str, rules: list[Rule], rule_id: str) -> list[Finding]:
    """Get all findings for a specific rule on a line."""
    return [f for f in match_line(line, 1, "test.md", rules) if f.rule_id == rule_id]
```

### Files to update (replace local `_match`/`_findings` with imports)

1. tests/unit/test_rules_cred_detection.py
2. tests/unit/test_rules_exec_detection.py
3. tests/unit/test_rules_exec_persistence.py
4. tests/unit/test_rules_exec_advanced.py
5. tests/unit/test_rules_js_execution.py
6. tests/unit/test_rules_exfil_detection.py
7. tests/unit/test_rules_exfil_advanced.py
8. tests/unit/test_rules_supply_chain_detection.py
9. tests/unit/test_rules_pi_advanced.py
10. tests/unit/test_rules_tool_abuse.py

Each file: delete local `_match`/`_findings` functions, add `from tests.unit.rule_helpers import match_rule, rule_findings`, rename call sites from `_match(` to `match_rule(` and `_findings(` to `rule_findings(`.

### Verification
- `make check` passes
- Same test count, same behavior

## Part 3: Strengthen Weak Assertions

### 3a. Scanner integration tests — tighten assertions

**tests/unit/test_scanner.py:**
- Line 34: change `assert any(f.category == "prompt-injection" for f in result.findings)` to also check `f.file == "SKILL.md"`
- Line 45-46: change `assert any(f.file == "script.py" ...)` to `assert any(f.file == "script.py" and f.category == "prompt-injection" ...)`
- Lines 113-114: add category assertions (`f.category != "file-safety"`)

**tests/unit/test_scanner_custom_rules.py:**
- Line 43: change `>= 1` to `== 1`
- Line 44: add `assert custom_findings[0].file == "readme.md"`

### 3b. Rule detection tests — tighten `>= 1` to `== 1`

In the following files, change `assert len(findings) >= 1` to `assert len(findings) == 1` for single-pattern parametrized inputs:
- test_rules_exec_detection.py
- test_rules_exec_persistence.py
- test_rules_exec_advanced.py
- test_rules_js_execution.py
- test_rules_exfil_detection.py
- test_rules_exfil_advanced.py
- test_rules_supply_chain_detection.py
- test_rules_tool_abuse.py

Note: only change for tests where a single line is matched against a single rule. Leave `>= 1` in place where comments indicate multiple matches are expected.

### 3c. Fix `assert True` anti-pattern

**tests/unit/test_github_api.py:**
- Line 46: remove `assert True` from `test_accepts_normal_name`
- Line 51: remove `assert True` from `test_accepts_double_dot_in_filename`
- The "no exception raised" contract is the real assertion

### 3d. Remove tautological frozen-dataclass test

**tests/unit/test_formatters_grouping.py:**
- Line 91: delete `test_scan_result_findings_preserved_unchanged` — frozen dataclass makes mutation impossible

### Verification
- `make check` passes
- If any `== 1` assertion fails, investigate whether the rule fires multiple times on a single line (a real engine issue, not a test problem)

## Part 4: Merge Small Files + Move Misplaced Tests

### 4a. Merge test_formatters_coverage.py into test_formatters_summary.py

`test_formatters_coverage.py` is only 42 lines. Move all its test classes into `test_formatters_summary.py` (currently 124 lines — combined ~160, well under 250). Delete `test_formatters_coverage.py`.

### 4b. Move TestParseSource to correct file

Move `TestParseSource` class (tests/unit/test_github_fetcher.py lines 19-57) into `tests/unit/test_github_api.py`. It tests `_github_api.parse_source`, not `_fetchers.py`.

### 4c. Move TestPublicAPI to correct file

Move `TestPublicAPI` class from `tests/integration/test_cli_json_format.py` (lines 17-27) to `tests/integration/test_cli.py`. It tests the Python API, not JSON formatting.

### 4d. Remove duplicate JSON schema test

Delete `test_format_json_has_required_fields` from `tests/integration/test_cli_json_format.py` (line 42) — identical assertion exists in `tests/unit/test_json_formatter.py:18`.

### 4e. Move TestPublicAPIImports out of formatters

Move `TestPublicAPIImports` from `tests/unit/test_formatters.py` (line 215) to a more appropriate location — either `tests/unit/test_models.py` (if room) or leave in place with a comment. This frees ~25 lines of headroom in the near-limit test_formatters.py.

### Verification
- `make check` passes
- File count reduced by 1 (test_formatters_coverage.py deleted)
- No orphan imports

## Execution Order

Part 1 (deletions) first — frees line budget for Part 4 moves. Part 2 (DRY) is independent. Part 3 (assertions) is independent. Part 4 (moves) last — depends on Part 1 freeing space.

## Expected Outcome

- ~16 fewer tests (14 deletes + 2 tautologies)
- ~1 fewer test file (test_formatters_coverage.py merged)
- 9 files get DRY helper consolidation
- ~15 assertions tightened from `>= 1` to `== 1`
- 4 test classes in correct files
- `make check` green throughout
