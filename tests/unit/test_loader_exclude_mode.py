"""Unit tests for exclude_mode field in rule loader.

Tests verify that the exclude_mode field is correctly parsed from TOML
rule definitions and defaults to "default" when not specified.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.rules.loader import load_rules


def write_toml(path: Path, content: str) -> Path:
    """Helper to write TOML content to a file."""
    path.write_text(content)
    return path


def make_simple_rule(
    rule_id: str = "TEST-001",
    severity: str = "info",
    patterns: list[str] | None = None,
    exclude_mode: str | None = None,
) -> str:
    """Generate a minimal TOML rule definition."""
    patterns_str = '", "'.join(patterns or ["test"])
    exclude_mode_line = f'\nexclude_mode = "{exclude_mode}"' if exclude_mode else ""
    return f"""
        [rules.{rule_id}]
        severity = "{severity}"
        category = "test"
        description = "Test"
        recommendation = "Test"
        patterns = ["{patterns_str}"]{exclude_mode_line}
    """


class TestExcludeModeLoading:
    """Tests for exclude_mode field parsing in rule loader."""

    def test_exclude_mode_parsed_from_toml(self, tmp_path: Path) -> None:
        """Rule with exclude_mode='strict' in TOML is parsed correctly."""
        toml_path = write_toml(
            tmp_path / "test.toml",
            """
            [rules.TEST-001]
            severity = "info"
            category = "test"
            description = "Test"
            recommendation = "Test"
            patterns = ["pattern"]
            exclude_mode = "strict"
            """,
        )

        rules = load_rules(toml_path)

        assert rules[0].exclude_mode == "strict"

    def test_exclude_mode_defaults_to_default(self, tmp_path: Path) -> None:
        """Rule without exclude_mode field defaults to 'default'."""
        toml_path = write_toml(tmp_path / "test.toml", make_simple_rule())

        rules = load_rules(toml_path)

        assert rules[0].exclude_mode == "default"

    def test_invalid_exclude_mode_raises_value_error(self, tmp_path: Path) -> None:
        """Rule with invalid exclude_mode value raises ValueError."""
        toml_path = write_toml(
            tmp_path / "test.toml",
            """
            [rules.TEST-001]
            severity = "info"
            category = "test"
            description = "Test"
            recommendation = "Test"
            patterns = ["pattern"]
            exclude_mode = "invalid"
            """,
        )

        with pytest.raises(ValueError, match="Invalid exclude_mode"):
            load_rules(toml_path)

    def test_exclude_mode_default_value_parsed(self, tmp_path: Path) -> None:
        """Rule with explicit exclude_mode='default' is parsed correctly."""
        toml_path = write_toml(tmp_path / "test.toml", make_simple_rule(exclude_mode="default"))

        rules = load_rules(toml_path)

        assert rules[0].exclude_mode == "default"
