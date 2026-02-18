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

    def test_rules_md_is_fresh(self) -> None:
        """RULES.md matches generated output. Run `make rules-catalog` to fix."""
        rules_md = _REPO_ROOT / "RULES.md"
        if not rules_md.exists():
            pytest.skip("RULES.md not found")

        # Import the generator script
        sys.path.insert(0, str(_REPO_ROOT / "scripts"))
        from generate_rules_catalog import generate_catalog  # type: ignore[import-not-found]

        expected = generate_catalog()
        actual = rules_md.read_text(encoding="utf-8")
        assert actual == expected, "RULES.md is stale. Run `make rules-catalog` to regenerate."
