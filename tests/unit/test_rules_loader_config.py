"""Unit tests for load_rules_from_config -- custom rule loading from config data."""

from __future__ import annotations

from skill_scan.models import Rule, Severity
from skill_scan.rules.loader import load_rules_from_config


class TestLoadRulesFromConfig:
    """Tests for load_rules_from_config function."""

    def test_valid_rules_section_returns_rules(self) -> None:
        """Parses [rules.*] sections into Rule objects."""
        data: dict[str, object] = {
            "rules": {
                "CUSTOM-001": {
                    "severity": "high",
                    "category": "custom",
                    "description": "Test custom rule",
                    "recommendation": "Fix it",
                    "patterns": ["test_pattern"],
                },
            },
        }

        rules = load_rules_from_config(data)

        assert len(rules) == 1
        assert isinstance(rules[0], Rule)
        assert rules[0].rule_id == "CUSTOM-001"
        assert rules[0].severity == Severity.HIGH
        assert rules[0].category == "custom"
        assert rules[0].description == "Test custom rule"

    def test_multiple_rules_sorted_by_id(self) -> None:
        """Multiple custom rules are returned sorted by rule_id."""
        data: dict[str, object] = {
            "rules": {
                "CUSTOM-002": {
                    "severity": "medium",
                    "category": "custom",
                    "description": "Second",
                    "recommendation": "Fix",
                    "patterns": ["b"],
                },
                "CUSTOM-001": {
                    "severity": "high",
                    "category": "custom",
                    "description": "First",
                    "recommendation": "Fix",
                    "patterns": ["a"],
                },
            },
        }

        rules = load_rules_from_config(data)

        assert len(rules) == 2
        assert rules[0].rule_id == "CUSTOM-001"
        assert rules[1].rule_id == "CUSTOM-002"

    def test_empty_rules_section_returns_empty_list(self) -> None:
        """Empty [rules] section returns empty list."""
        data: dict[str, object] = {"rules": {}}

        rules = load_rules_from_config(data)

        assert rules == []

    def test_missing_rules_section_returns_empty_list(self) -> None:
        """Data without [rules] key returns empty list."""
        data: dict[str, object] = {"scan": {"max_file_size": 100_000}}

        rules = load_rules_from_config(data)

        assert rules == []

    def test_rules_not_dict_returns_empty_list(self) -> None:
        """Non-dict rules value returns empty list."""
        data: dict[str, object] = {"rules": "not a dict"}

        rules = load_rules_from_config(data)

        assert rules == []

    def test_patterns_are_compiled_regex(self) -> None:
        """Patterns in custom rules are compiled to regex objects."""
        data: dict[str, object] = {
            "rules": {
                "CUSTOM-001": {
                    "severity": "info",
                    "category": "custom",
                    "description": "Test",
                    "recommendation": "Test",
                    "patterns": ["foo\\s+bar"],
                },
            },
        }

        rules = load_rules_from_config(data)

        assert len(rules[0].patterns) == 1
        assert rules[0].patterns[0].search("foo  bar") is not None
        assert rules[0].patterns[0].search("foobar") is None
