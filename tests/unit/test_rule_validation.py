"""Validate all built-in rule definition files load without error.

Catches field typos, invalid regexes, and bad enum values at CI time
rather than at runtime. Parametrized per-file so failures identify
which file is broken. Also checks RULES.md freshness.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from skill_scan.rules.loader import load_default_rules, load_rules

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DATA_DIR = _REPO_ROOT / "src" / "skill_scan" / "rules" / "data"
_TOML_FILES = sorted(_DATA_DIR.glob("*.toml"))


@pytest.mark.parametrize("toml_file", _TOML_FILES, ids=[f.stem for f in _TOML_FILES])
class TestRuleFileValidation:
    """Per-file validation of TOML rule definitions."""

    def test_loads_without_error(self, toml_file: Path) -> None:
        """load_rules() succeeds (validates fields, severity, regexes)."""
        rules = load_rules(toml_file)
        assert len(rules) > 0, f"{toml_file.name} produced zero rules"

    def test_rules_have_patterns(self, toml_file: Path) -> None:
        """Every rule must have at least one detection pattern."""
        for rule in load_rules(toml_file):
            assert len(rule.patterns) > 0, f"{rule.rule_id} has no patterns"

    def test_rules_have_descriptions(self, toml_file: Path) -> None:
        """Every rule must have non-empty description and recommendation."""
        for rule in load_rules(toml_file):
            assert rule.description.strip(), f"{rule.rule_id} has empty description"
            assert rule.recommendation.strip(), f"{rule.rule_id} has empty recommendation"


class TestRuleUniqueness:
    """Cross-file validation."""

    def test_no_duplicate_rule_ids(self) -> None:
        """All rule IDs across all files must be unique."""
        all_rules = load_default_rules()
        ids = [r.rule_id for r in all_rules]
        duplicates = [rid for rid in set(ids) if ids.count(rid) > 1]
        assert not duplicates, f"Duplicate rule IDs: {sorted(duplicates)}"

    def test_minimum_rule_count(self) -> None:
        """Sanity check: expected number of pattern-based rules."""
        all_rules = load_default_rules()
        assert len(all_rules) >= 60, f"Expected 60+ rules, got {len(all_rules)}"


class TestRulesCatalog:
    """Verify RULES.md stays in sync with generated output."""

    @pytest.fixture(autouse=True)
    def _import_catalog(self) -> None:
        """Import catalog generator and make it available to all tests."""
        sys.path.insert(0, str(_REPO_ROOT / "scripts"))
        import generate_rules_catalog as mod  # type: ignore[import-not-found]

        self._catalog_mod = mod

    def test_rules_md_is_fresh(self) -> None:
        """RULES.md matches generated output. Run `make rules-catalog` to fix."""
        rules_md = _REPO_ROOT / "RULES.md"
        if not rules_md.exists():
            pytest.skip("RULES.md not found")

        expected = self._catalog_mod.generate_catalog()
        actual = rules_md.read_text(encoding="utf-8")
        assert actual == expected, "RULES.md is stale. Run `make rules-catalog` to regenerate."

    def test_obfs001_in_procedural_rules(self) -> None:
        """OBFS-001 entry exists in _PROCEDURAL_RULES with correct metadata."""
        rules = self._catalog_mod._PROCEDURAL_RULES
        obfs = [r for r in rules if r.rule_id == "OBFS-001"]
        assert len(obfs) == 1, "OBFS-001 must appear exactly once in _PROCEDURAL_RULES"
        entry = obfs[0]
        assert entry.severity == "high"
        assert entry.category == "obfuscation"
        assert entry.confidence == "stable"
        assert entry.source == "procedural"

    def test_obfs001_in_obfuscation_section(self) -> None:
        """Generated catalog places OBFS-001 in the Obfuscation section."""
        groups = self._catalog_mod.collect_rules()
        obfuscation_ids = [r.rule_id for r in groups.get("obfuscation", [])]
        assert "OBFS-001" in obfuscation_ids

    def test_no_missing_ast_procedural_rules(self) -> None:
        """All AST-only rule IDs are covered by _PROCEDURAL_RULES or TOML rules."""
        # AST detectors emit these rule IDs
        ast_rule_ids = {"EXEC-002", "EXEC-006", "EXEC-007", "OBFS-001"}
        # Collect all rule IDs from TOML + procedural
        groups = self._catalog_mod.collect_rules()
        all_catalog_ids = {r.rule_id for rules in groups.values() for r in rules}
        missing = ast_rule_ids - all_catalog_ids
        assert not missing, f"AST rule IDs missing from catalog: {sorted(missing)}"
