# Plan: Migrate Rule Definitions from TOML to JSON with Schema Validation

## Context

A PR reviewer flagged that rule/category IDs are duplicated as hardcoded strings across multiple Python modules (`scanner.py`, `content_scanner.py`, `file_collector.py`, `file_checks.py`), risking silent drift. Investigation revealed a deeper opportunity: the built-in rule definitions live in TOML files which offer no structural validation — a contributor can add a rule, misspell a field name, and only discover it at runtime.

For an open-source security tool used by inexperienced users, the codebase needs to inspire confidence. Migrating to JSON enables **JSON Schema validation** — every rule file can be machine-validated for required fields, correct types, and valid enum values before any code runs.

**Scope:** Built-in rule data files only. User config files (`--config`) stay TOML.

## Parts

### Part 1: JSON Schema + TOML-to-JSON conversion

**Create the JSON Schema** at `src/skill_scan/rules/data/rule_schema.json`:

```jsonc
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
- All rules get `"type": "pattern"` (explicit for clarity)

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
    }
    // ... FS-003 through FS-008
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

Procedural rules use `"type": "procedural"` and template strings in `description` (e.g., `{file_path}`, `{error}`). They have no `patterns` field.

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

**Modify** `src/skill_scan/scanner.py` (currently 105 lines):
- Import `get_rule` from `rule_registry`
- Remove `_RULE_BINARY`, `_RULE_SCHEMA`, `_CATEGORY_SCHEMA` constants
- Use `get_rule("SV-001")` for schema validation finding
- For binary skip counting: `sum(1 for f in fs_findings if f.rule_id == "FS-002")` — the literal is fine here since it's a query, not metadata construction. Alternatively import the constant from the Rule object.

**Modify** `src/skill_scan/file_collector.py` (currently 104 lines):
- Replace hardcoded `_SKIP_CONTENT_RULES = frozenset({"FS-002", "FS-004", "FS-005"})` with a set derived from loaded rules: `_SKIP_CONTENT_RULES = frozenset(r.rule_id for r in load_default_rules() if r.skip_content_scan)`
- Or: build this set lazily similar to the registry

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

**14 test files** reference `.toml`:

**9 rule-detection test files** with hardcoded `RULES_PATH` to `.toml`:
- Change file extension from `.toml` to `.json` in the path
- Change `load_rules(path)` calls — these now load JSON (the loader handles it)

**`test_rules_loader.py`** (250 lines, AT LIMIT):
- `write_toml()` helper → `write_json()` helper
- `make_simple_rule()` returns JSON string instead of TOML string
- Test names/docstrings updated
- Since this file is at the line limit, the format change may net-save lines (JSON helper is simpler than TOML string construction)

**`test_loader_exclude_mode.py`**:
- Same pattern: TOML helpers → JSON helpers

**`test_config.py`** and `test_cli_config.py`**:
- User config tests stay TOML (user config format unchanged)
- Only tests that load built-in rules need updating

**Test fixture files** in `tests/fixtures/configs/`:
- `custom_rule.toml`, `suppress.toml`, `scan_settings.toml` — **unchanged** (user config stays TOML)

---

## Files Modified

| File | Action | Current Lines |
|------|--------|--------------|
| `src/skill_scan/rules/data/*.toml` (10 files) | Delete | — |
| `src/skill_scan/rules/data/*.json` (12 files) | Create | — |
| `src/skill_scan/rules/data/rule_schema.json` | Create | ~40 |
| `src/skill_scan/rule_registry.py` | Create | ~35-45 |
| `src/skill_scan/rules/loader.py` | Modify | 180 → ~175 |
| `src/skill_scan/models.py` | Modify | 75 → ~78 |
| `src/skill_scan/file_checks.py` | Modify | 113 → ~105 |
| `src/skill_scan/content_scanner.py` | Modify | 84 → ~80 |
| `src/skill_scan/scanner.py` | Modify | 105 → ~100 |
| `src/skill_scan/file_collector.py` | Modify | 104 → ~100 |
| `pyproject.toml` | Modify (add jsonschema dev dep) | — |
| `tests/unit/test_rule_schema.py` | Create | ~40-50 |
| `tests/unit/test_rules_loader.py` | Modify | 250 → ~245 |
| `tests/unit/test_loader_exclude_mode.py` | Modify | — |
| 9 `tests/unit/test_rules_*.py` files | Modify (path ext change) | — |

All files stay well within the 250-line budget.

## Verification

1. `make check` — all pre-commit hooks pass (ruff, mypy, bandit)
2. `pytest` — all 1677+ existing tests pass (no regressions)
3. New `test_rule_schema.py` validates all JSON files against schema
4. Manual: `skill-scan <path>` produces identical output before/after migration
5. Manual: `skill-scan --config <toml_config>` still works (user config unchanged)
6. Verify no `.toml` files remain in `src/skill_scan/rules/data/`
7. Verify no hardcoded rule IDs remain in `file_checks.py`, `content_scanner.py` (except registry lookups)
