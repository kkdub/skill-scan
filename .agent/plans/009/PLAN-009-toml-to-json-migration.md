# Plan 009: Migrate Rule Definitions from TOML to JSON with Schema Validation

## Context

A PR reviewer flagged that rule/category IDs are duplicated as hardcoded strings across multiple Python modules (`scanner.py`, `content_scanner.py`, `file_collector.py`, `file_checks.py`), risking silent drift. Investigation revealed a deeper opportunity: the built-in rule definitions live in TOML files which offer no structural validation — a contributor can add a rule, misspell a field name, and only discover it at runtime.

For an open-source security tool used by inexperienced users, the codebase needs to inspire confidence. Migrating to JSON enables **JSON Schema validation** — every rule file can be machine-validated for required fields, correct types, and valid enum values before any code runs.

**Scope:** Built-in rule data files only. User config files (`--config`) stay TOML.

## Current State (post file_collector/file_classifier refactor)

Key files and their current roles:
- `scanner.py` — orchestration; hardcodes `_RULE_BINARY="FS-002"`, `_RULE_SCHEMA="SV-001"`, `_CATEGORY_SCHEMA="schema-validation"`
- `content_scanner.py` — file reading + rule matching; hardcodes `_RULE_ENCODING_ERROR="FS-001"`, `_RULE_READ_ERROR="FS-008"`, `_CATEGORY_FILE_SAFETY="file-safety"`
- `file_classifier.py` — pure classification decisions; owns `_SKIP_CONTENT_RULES = frozenset({"FS-002", "FS-004", "FS-005"})`
- `file_checks.py` — pure per-file check functions; hardcodes rule_id, severity, category, description, recommendation in each Finding
- `file_collector.py` — I/O only walker (no rule IDs)
- `rules/loader.py` — loads TOML rule files, compiles regex patterns into Rule objects
- `models.py` — Finding, Rule, ScanResult, FileEntry dataclasses

Duplicated IDs with real drift risk:
- `"FS-002"` appears in 3 files (file_checks.py, scanner.py, file_classifier.py)
- `"file-safety"` appears in 2 files (file_checks.py x6, content_scanner.py)
- `"FS-004"`, `"FS-005"` appear in both file_checks.py and file_classifier.py

## Parts

### Part 1: JSON Schema + TOML-to-JSON conversion

**Create the JSON Schema** at `src/skill_scan/rules/data/rule_schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["rules"],
  "additionalProperties": false,
  "properties": {
    "rules": {
      "type": "object",
      "minProperties": 1,
      "additionalProperties": {
        "$ref": "#/$defs/rule"
      }
    }
  },
  "$defs": {
    "rule": {
      "type": "object",
      "required": ["severity", "category", "description", "recommendation"],
      "additionalProperties": false,
      "properties": {
        "severity":      { "enum": ["critical", "high", "medium", "low", "info"] },
        "category":      { "type": "string", "minLength": 1 },
        "description":   { "type": "string", "minLength": 1 },
        "recommendation":{ "type": "string", "minLength": 1 },
        "patterns":             { "type": "array", "items": { "type": "string" } },
        "exclude_patterns":     { "type": "array", "items": { "type": "string" } },
        "path_exclude_patterns":{ "type": "array", "items": { "type": "string" } },
        "flags":         { "type": "string" },
        "confidence":    { "enum": ["stable", "beta"], "default": "stable" },
        "match_scope":   { "enum": ["line", "file"], "default": "line" },
        "exclude_mode":  { "enum": ["default", "strict"], "default": "default" },
        "type":          { "enum": ["pattern", "procedural"], "default": "pattern" },
        "skip_content_scan": { "type": "boolean", "default": false }
      }
    }
  }
}
```

**Convert 10 TOML files to JSON** (1:1 mapping, same filenames):
- `prompt_injection.toml` → `prompt_injection.json`
- `prompt_injection_cjk.toml` → `prompt_injection_cjk.json`
- `prompt_injection_european.toml` → `prompt_injection_european.json`
- `prompt_injection_other.toml` → `prompt_injection_other.json`
- `credential_exposure.toml` → `credential_exposure.json`
- `supply_chain.toml` → `supply_chain.json`
- `javascript_execution.toml` → `javascript_execution.json`
- `tool_abuse.toml` → `tool_abuse.json`
- `malicious_code.toml` → `malicious_code.json`
- `data_exfiltration.toml` → `data_exfiltration.json`

**Delete the 10 `.toml` files** after conversion.

**Conversion notes:**
- TOML `[rules.JSEXEC-001]` → JSON `{"rules": {"JSEXEC-001": {...}}}`
- Regex backslashes must be double-escaped: TOML `'\beval\s*\('` → JSON `"\\beval\\s*\\("`
- All pattern rules get `"type": "pattern"` (explicit for clarity)

**Add 2 new JSON files for procedural rules:**

`file_safety.json` — rules FS-001 through FS-008:
```json
{
  "rules": {
    "FS-001": {
      "type": "procedural",
      "severity": "medium",
      "category": "file-safety",
      "description": "File is not valid UTF-8 and was skipped.",
      "recommendation": "Verify file encoding or exclude from scan."
    },
    "FS-002": {
      "type": "procedural",
      "severity": "high",
      "category": "file-safety",
      "description": "Binary file detected: {file_path}",
      "recommendation": "Remove binary files or provide source code instead.",
      "skip_content_scan": true
    },
    "FS-003": {
      "type": "procedural",
      "severity": "medium",
      "category": "file-safety",
      "description": "Unknown file extension '{suffix}' in {file_path}",
      "recommendation": "Verify this file type is expected, or add it to allowed extensions."
    },
    "FS-004": {
      "type": "procedural",
      "severity": "high",
      "category": "file-safety",
      "description": "Symlink points outside skill directory: {file_path}",
      "recommendation": "Remove symlinks that reference files outside the skill root.",
      "skip_content_scan": true
    },
    "FS-005": {
      "type": "procedural",
      "severity": "medium",
      "category": "file-safety",
      "description": "File exceeds size limit ({size:,} bytes > {limit:,} bytes): {file_path}",
      "recommendation": "Reduce file size or adjust max_file_size in config.",
      "skip_content_scan": true
    },
    "FS-006": {
      "type": "procedural",
      "severity": "medium",
      "category": "file-safety",
      "description": "Total skill size exceeds limit ({total_size:,} bytes > {limit:,} bytes)",
      "recommendation": "Reduce total file size or adjust max_total_size in config."
    },
    "FS-007": {
      "type": "procedural",
      "severity": "medium",
      "category": "file-safety",
      "description": "File count exceeds limit ({count} > {limit})",
      "recommendation": "Reduce number of files or adjust max_file_count in config."
    },
    "FS-008": {
      "type": "procedural",
      "severity": "medium",
      "category": "file-safety",
      "description": "File could not be read: {error_type}",
      "recommendation": "Check file permissions and accessibility."
    }
  }
}
```

`schema_validation.json` — rule SV-001:
```json
{
  "rules": {
    "SV-001": {
      "type": "procedural",
      "severity": "medium",
      "category": "schema-validation",
      "description": "Schema validation failed: {error}",
      "recommendation": "Fix frontmatter in SKILL.md or use 'skill-scan validate' for details"
    }
  }
}
```

Procedural rules use `"type": "procedural"` and template strings in `description` (e.g., `{file_path}`, `{error}`). They have no `patterns` field. The `skip_content_scan` field marks rules where a finding means the file should not be content-scanned.

**Files created:** 13 JSON files (10 converted + 2 procedural + 1 schema)
**Files deleted:** 10 TOML files

---

### Part 2: Update loader for JSON

**Modify** `src/skill_scan/rules/loader.py`:

1. Replace `import tomllib` with `import json`
2. `load_rules(path)`: read with `json.load()` instead of `tomllib.load()`
3. `load_default_rules()`: glob `*.json` instead of `*.toml`, skip `rule_schema.json`
4. `_parse_rule()`: add handling for `type` and `skip_content_scan` fields — store them on the Rule model
5. Keep `load_rules_from_config()` unchanged — it still receives a dict from the TOML config parser

**Modify** `src/skill_scan/models.py` — add fields to `Rule`:
```python
rule_type: str = "pattern"          # "pattern" or "procedural"
skip_content_scan: bool = False     # True for FS-002, FS-004, FS-005
```

**Key:** `load_rules_from_config()` stays as-is. It already takes a `dict`, not a file. The user config path (`config.py` → `tomllib.load()` → dict → `load_rules_from_config(dict)`) is unaffected.

---

### Part 3: Rule registry for procedural lookups

**Create** `src/skill_scan/rule_registry.py` (~35-45 lines):

```python
"""Procedural rule metadata registry — loaded from JSON at import time.

Provides lookup of rule metadata (severity, category, description template,
recommendation) for procedural rules (FS-*, SV-*) that don't use the
regex pattern-matching engine.
"""

from skill_scan.rules import load_default_rules
from skill_scan.models import Rule

_REGISTRY: dict[str, Rule] | None = None

def get_rule(rule_id: str) -> Rule:
    """Look up a rule by ID. Returns the Rule object."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = {r.rule_id: r for r in load_default_rules()}
    return _REGISTRY[rule_id]
```

This is a lazy-loaded singleton that builds the index on first access. All procedural code imports `get_rule("FS-002")` to get metadata instead of hardcoding strings.

---

### Part 4: Refactor procedural code to use registry

**Modify** `src/skill_scan/file_checks.py` (currently 113 lines):
- Import `get_rule` from `rule_registry`
- Each function looks up rule metadata: `rule = get_rule("FS-002")`
- Construct Finding using `rule.severity`, `rule.category`, `rule.recommendation`
- Format description from template: `rule.description.format(file_path=file_path)`
- Remove all hardcoded severity/category/description/recommendation strings

**Modify** `src/skill_scan/content_scanner.py` (currently 84 lines):
- Import `get_rule` from `rule_registry`
- Remove `_RULE_ENCODING_ERROR`, `_RULE_READ_ERROR`, `_CATEGORY_FILE_SAFETY` constants
- Use `get_rule("FS-001")` and `get_rule("FS-008")` for metadata

**Modify** `src/skill_scan/scanner.py` (currently ~105 lines):
- Import `get_rule` from `rule_registry`
- Remove `_RULE_BINARY`, `_RULE_SCHEMA`, `_CATEGORY_SCHEMA` constants
- Use `get_rule("SV-001")` for schema validation finding
- For binary skip counting: `sum(1 for f in fs_findings if f.rule_id == "FS-002")` — the literal is fine here since it's a query, not metadata construction

**Modify** `src/skill_scan/file_classifier.py`:
- Replace hardcoded `_SKIP_CONTENT_RULES = frozenset({"FS-002", "FS-004", "FS-005"})` with a set derived from loaded rules: build from `skip_content_scan` field on Rule objects
- Could use the registry or derive at module level

---

### Part 5: Add schema validation test + jsonschema dev dependency

**Add `jsonschema`** to `pyproject.toml` dev dependencies:
```toml
"jsonschema>=4.0,<5.0"
```

**Create** `tests/unit/test_rule_schema.py` (~40-50 lines):
- Load `rule_schema.json`
- Validate every `*.json` rule file in `src/skill_scan/rules/data/` against the schema
- Test that invalid rule data (missing required fields, bad severity, wrong types) fails validation
- This runs in CI and catches structural errors before code ever touches them

---

### Part 6: Update existing tests

**9 rule-detection test files** with hardcoded `RULES_PATH` to `.toml`:
- `test_rules_cred_detection.py` → credential_exposure.json
- `test_rules_exec_advanced.py` → malicious_code.json
- `test_rules_exfil_advanced.py` → data_exfiltration.json
- `test_rules_exec_detection.py` → malicious_code.json
- `test_rules_exfil_detection.py` → data_exfiltration.json
- `test_rules_exec_persistence.py` → malicious_code.json
- `test_rules_pi_advanced.py` → prompt_injection.json
- `test_rules_tool_abuse.py` → tool_abuse.json
- `test_rules_supply_chain_detection.py` → supply_chain.json

Change: file extension in `RULES_PATH` from `.toml` to `.json`

**`test_rules_loader.py`** (250 lines, AT LIMIT):
- `write_toml()` helper → `write_json()` helper
- `make_simple_rule()` returns JSON dict instead of TOML string
- Format change may net-save lines (JSON helper is simpler than TOML string construction)

**`test_loader_exclude_mode.py`**:
- Same pattern: TOML helpers → JSON helpers

**Test fixture files** in `tests/fixtures/configs/`:
- `custom_rule.toml`, `suppress.toml`, `scan_settings.toml` — **unchanged** (user config stays TOML)

---

## Files Summary

| File | Action | Notes |
|------|--------|-------|
| `src/skill_scan/rules/data/*.toml` (10 files) | Delete | Replaced by JSON |
| `src/skill_scan/rules/data/*.json` (12 files) | Create | 10 converted + 2 procedural |
| `src/skill_scan/rules/data/rule_schema.json` | Create | JSON Schema ~40 lines |
| `src/skill_scan/rule_registry.py` | Create | ~35-45 lines |
| `src/skill_scan/rules/loader.py` | Modify | tomllib → json |
| `src/skill_scan/models.py` | Modify | +2 fields on Rule |
| `src/skill_scan/file_checks.py` | Modify | Use registry lookups |
| `src/skill_scan/content_scanner.py` | Modify | Use registry lookups |
| `src/skill_scan/scanner.py` | Modify | Use registry lookups |
| `src/skill_scan/file_classifier.py` | Modify | Derive skip set from Rule data |
| `pyproject.toml` | Modify | Add jsonschema dev dep |
| `tests/unit/test_rule_schema.py` | Create | ~40-50 lines |
| `tests/unit/test_rules_loader.py` | Modify | TOML helpers → JSON helpers |
| `tests/unit/test_loader_exclude_mode.py` | Modify | TOML helpers → JSON helpers |
| 9 `tests/unit/test_rules_*.py` files | Modify | Path extension .toml → .json |

All files stay well within the 250-line budget.

## Verification

1. `make check` — all pre-commit hooks pass (ruff, mypy, bandit)
2. `pytest` — all 1677+ existing tests pass (no regressions)
3. New `test_rule_schema.py` validates all JSON files against schema
4. Manual: `skill-scan <path>` produces identical output before/after migration
5. Manual: `skill-scan --config <toml_config>` still works (user config unchanged)
6. Verify no `.toml` files remain in `src/skill_scan/rules/data/`
7. Verify no hardcoded rule metadata (severity/category/description/recommendation) remains in `file_checks.py`, `content_scanner.py`, `scanner.py`
