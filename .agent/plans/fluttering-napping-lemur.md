# PLAN-009r: Rule Discoverability, Authoring Aid, and CI Validation

**Supersedes:** PLAN-009 (TOML-to-JSON migration) — format migration dropped after
assessment showed it doesn't advance the actual goals and degrades regex readability.

## Context

A user wanting to add a rule today must: open 10 individual TOML files to check
what exists, reverse-engineer the field format from examples, and hope they didn't
typo a field name (discovered only at runtime). There's no catalog, no template,
and no CI validation of rule file structure.

**Goals:**
1. Discoverability — one place to see all rules
2. Authoring — a copy-paste template with documented fields
3. Validation — catch structural errors in CI, not at runtime

**What we're NOT doing:** No format migration (TOML stays), no CLI changes, no
new production dependencies, no changes to existing rule files or production code.

## Parts

### Part a: Rule authoring template

**Create:** `src/skill_scan/rules/template.toml` (~55 lines)

A commented TOML file documenting every field `_parse_rule()` accepts
([loader.py:100-131](src/skill_scan/rules/loader.py#L100-L131)). One complete
`[rules.EXAMPLE-001]` section with required fields filled and optional fields
commented out with their defaults and valid values.

Lives outside `data/` so `load_default_rules()` (which globs `data/*.toml`) won't
load it. Ships with the package for discoverability.

**Criteria:**
- File exists at `src/skill_scan/rules/template.toml`
- `load_default_rules()` does NOT include EXAMPLE-001
- Every field from `_parse_rule()` is documented
- Valid TOML (pre-commit check-toml passes)
- Under 250 lines

### Part b: CI validation test

**Create:** `tests/unit/test_rule_validation.py` (~55 lines)

Parametrized per TOML file so failures name the broken file. Uses the existing
`load_rules()` which already validates required fields, severity enum, regex
compilation, match_scope, and exclude_mode. No new dependency.

**Checks:**
1. `load_rules(path)` succeeds and returns non-empty list (per file)
2. Every rule has at least one pattern
3. Every rule has non-empty description and recommendation
4. No duplicate rule IDs across all files (cross-file test)

**Criteria:**
- File exists at `tests/unit/test_rule_validation.py`
- Parametrized per TOML file
- `make check` passes
- Under 250 lines

### Part c: Rules catalog

**Create:** `scripts/generate_rules_catalog.py` (~120 lines)
**Create:** `RULES.md` (generated, committed at repo root)
**Modify:** `Makefile` — add `rules-catalog` target

The script:
- Calls `load_default_rules()` for pattern-based rules (64 rules across 10 TOML files)
- Has static metadata for 9 procedural rules (FS-001..008, SV-001)
- Groups by category in fixed display order
- Renders markdown tables: Rule ID | Severity | Description | Confidence
- Header explains the catalog; footer points to `template.toml` for authoring
- Auto-generated warning so people don't hand-edit

**Makefile addition:**
```makefile
rules-catalog:
	$(PYTHON) scripts/generate_rules_catalog.py > RULES.md
```

**Freshness check:** A test in `test_rule_validation.py` that imports the
generator, runs it in-memory, and compares output to committed `RULES.md`.
Fails with "run `make rules-catalog` to fix" if stale.

**Criteria:**
- Script under 250 lines
- RULES.md lists all ~73 rules (64 pattern + 9 procedural)
- Grouped by category with consistent column format
- `make rules-catalog` regenerates it
- Freshness test catches stale catalogs

### Part z: Verification

- `make check` passes
- `template.toml` not loaded by scanner
- All TOML rule files pass validation test
- RULES.md freshness test passes
- No production code modified
- All new files under 250 lines

## Files

| Action | Path |
|--------|------|
| CREATE | `src/skill_scan/rules/template.toml` |
| CREATE | `tests/unit/test_rule_validation.py` |
| CREATE | `scripts/generate_rules_catalog.py` |
| CREATE | `RULES.md` |
| MODIFY | `Makefile` (add target) |

**Forbidden:** All `src/` production code, existing test files, `pyproject.toml`,
rule data files, CLI, config.

## Key references

- `_parse_rule()` field definitions: [loader.py:100-131](src/skill_scan/rules/loader.py#L100-L131)
- `load_default_rules()` glob: [loader.py:77-93](src/skill_scan/rules/loader.py#L77-L93)
- FS-002..007 metadata: [file_checks.py](src/skill_scan/file_checks.py)
- FS-001, FS-008 metadata: [content_scanner.py](src/skill_scan/content_scanner.py)
- SV-001 metadata: [scanner.py:25,92-101](src/skill_scan/scanner.py#L25)
- Script conventions: [check_code_patterns.py](scripts/check_code_patterns.py) (sys.path, dataclass patterns)
- Existing TOML example: [credential_exposure.toml](src/skill_scan/rules/data/credential_exposure.toml)
