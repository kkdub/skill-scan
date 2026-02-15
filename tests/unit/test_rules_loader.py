"""Unit tests for skill_scan.rules.loader — rule loading from TOML files.

Tests TOML parsing, regex compilation, flag handling, and default rule discovery.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from skill_scan.models import Rule, Severity
from skill_scan.rules.loader import load_default_rules, load_rules


def write_toml(path: Path, content: str) -> Path:
    """Helper to write TOML content to a file."""
    path.write_text(content)
    return path


def make_simple_rule(
    rule_id: str = "TEST-001",
    severity: str = "info",
    patterns: list[str] | None = None,
    flags: str | None = None,
) -> str:
    """Generate a minimal TOML rule definition."""
    patterns_str = '", "'.join(patterns or ["test"])
    flags_line = f'\nflags = "{flags}"' if flags else ""
    return f"""
        [rules.{rule_id}]
        severity = "{severity}"
        category = "test"
        description = "Test"
        recommendation = "Test"
        patterns = ["{patterns_str}"]{flags_line}
    """


class TestLoadRules:
    """Tests for load_rules function — loading from a single TOML file."""

    def test_load_rules_with_single_rule(self, tmp_path: Path) -> None:
        toml_path = write_toml(
            tmp_path / "test.toml",
            """
            [rules.TEST-001]
            severity = "high"
            category = "test-category"
            description = "Test rule"
            recommendation = "Fix it"
            patterns = ["test_pattern"]
            exclude_patterns = ["safe_pattern"]
            """,
        )

        rules = load_rules(toml_path)

        assert len(rules) == 1
        assert rules[0].rule_id == "TEST-001"
        assert rules[0].severity == Severity.HIGH
        assert rules[0].category == "test-category"
        assert rules[0].description == "Test rule"
        assert rules[0].recommendation == "Fix it"

    def test_load_rules_with_multiple_rules_sorted_by_id(self, tmp_path: Path) -> None:
        toml_path = write_toml(
            tmp_path / "test.toml",
            make_simple_rule("ZZLAST", "low", ["z"])
            + make_simple_rule("AAFIRST", "high", ["a"])
            + make_simple_rule("MMIDDLE", "medium", ["m"]),
        )

        rules = load_rules(toml_path)

        assert len(rules) == 3
        assert [r.rule_id for r in rules] == ["AAFIRST", "MMIDDLE", "ZZLAST"]

    def test_load_rules_patterns_are_compiled_regex(self, tmp_path: Path) -> None:
        toml_path = write_toml(tmp_path / "test.toml", make_simple_rule(patterns=["test_\\\\w+"]))

        rules = load_rules(toml_path)
        pattern = rules[0].patterns[0]

        assert isinstance(pattern, re.Pattern)
        assert pattern.search("test_value") is not None
        assert pattern.search("not_matched") is None

    def test_load_rules_exclude_patterns_are_compiled(self, tmp_path: Path) -> None:
        toml_path = write_toml(
            tmp_path / "test.toml",
            """
            [rules.TEST-001]
            severity = "info"
            category = "test"
            description = "Test"
            recommendation = "Test"
            patterns = ["pattern"]
            exclude_patterns = ["safe_\\\\w+", "comment_\\\\d+"]
            """,
        )

        rules = load_rules(toml_path)

        assert len(rules[0].exclude_patterns) == 2
        assert rules[0].exclude_patterns[0].search("safe_area") is not None
        assert rules[0].exclude_patterns[0].search("unsafe") is None

    @pytest.mark.parametrize(
        "severity_str,expected_enum",
        [
            ("critical", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("medium", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
        ],
    )
    def test_load_rules_severity_string_maps_to_enum(
        self, tmp_path: Path, severity_str: str, expected_enum: Severity
    ) -> None:
        toml_path = write_toml(tmp_path / "test.toml", make_simple_rule(severity=severity_str))

        rules = load_rules(toml_path)

        assert rules[0].severity == expected_enum

    def test_load_rules_flag_ignorecase_applied_to_patterns(self, tmp_path: Path) -> None:
        toml_path = write_toml(
            tmp_path / "test.toml", make_simple_rule(patterns=["Test"], flags="IGNORECASE")
        )

        rules = load_rules(toml_path)
        pattern = rules[0].patterns[0]

        assert pattern.search("test") is not None
        assert pattern.search("TEST") is not None
        assert pattern.search("TeSt") is not None

    def test_load_rules_multiple_flags_pipe_separated(self, tmp_path: Path) -> None:
        toml_path = write_toml(
            tmp_path / "test.toml",
            make_simple_rule(patterns=["^test"], flags="IGNORECASE|MULTILINE"),
        )

        rules = load_rules(toml_path)
        pattern = rules[0].patterns[0]

        assert pattern.search("TEST") is not None
        assert pattern.search("line1\ntest") is not None

    def test_load_rules_multiple_flags_comma_separated(self, tmp_path: Path) -> None:
        toml_path = write_toml(
            tmp_path / "test.toml",
            make_simple_rule(patterns=["TEST"], flags="IGNORECASE, DOTALL"),
        )

        rules = load_rules(toml_path)

        assert rules[0].patterns[0].search("test") is not None

    def test_load_rules_no_flags_field_compiles_without_flags(self, tmp_path: Path) -> None:
        toml_path = write_toml(tmp_path / "test.toml", make_simple_rule(patterns=["Test"]))

        rules = load_rules(toml_path)
        pattern = rules[0].patterns[0]

        assert pattern.search("Test") is not None
        assert pattern.search("test") is None

    def test_load_rules_unknown_flag_raises_value_error(self, tmp_path: Path) -> None:
        toml_path = write_toml(tmp_path / "test.toml", make_simple_rule(flags="INVALID_FLAG"))

        with pytest.raises(ValueError, match="Unknown regex flag: INVALID_FLAG"):
            load_rules(toml_path)

    def test_load_rules_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_rules(tmp_path / "nonexistent.toml")

    def test_load_rules_empty_rules_table_returns_empty_list(self, tmp_path: Path) -> None:
        toml_path = write_toml(tmp_path / "test.toml", "[rules]")

        rules = load_rules(toml_path)

        assert rules == []

    def test_load_rules_no_rules_table_returns_empty_list(self, tmp_path: Path) -> None:
        toml_path = write_toml(tmp_path / "test.toml", '[other]\nkey = "value"')

        rules = load_rules(toml_path)

        assert rules == []

    def test_load_rules_invalid_regex_raises_value_error(self, tmp_path: Path) -> None:
        toml_path = write_toml(tmp_path / "test.toml", make_simple_rule(patterns=["(unclosed"]))

        with pytest.raises(ValueError, match="Invalid regex pattern"):
            load_rules(toml_path)

    def test_load_rules_patterns_and_exclude_patterns_applied_same_flags(self, tmp_path: Path) -> None:
        toml_path = write_toml(
            tmp_path / "test.toml",
            """
            [rules.TEST-001]
            severity = "info"
            category = "test"
            description = "Test"
            recommendation = "Test"
            patterns = ["Include"]
            exclude_patterns = ["Exclude"]
            flags = "IGNORECASE"
            """,
        )

        rules = load_rules(toml_path)

        assert rules[0].patterns[0].search("include") is not None
        assert rules[0].exclude_patterns[0].search("exclude") is not None


class TestLoadDefaultRules:
    """Tests for load_default_rules function — discovering built-in rules."""

    def test_load_default_rules_returns_list(self) -> None:
        rules = load_default_rules()

        assert isinstance(rules, list)

    def test_load_default_rules_all_items_are_rule_objects(self) -> None:
        rules = load_default_rules()

        for rule in rules:
            assert isinstance(rule, Rule)
