"""Tests for scan configuration."""

import dataclasses
import tomllib
from pathlib import Path

import pytest

from skill_scan.config import ScanConfig, load_config
from skill_scan.models import Severity

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "configs"


def test_scan_config_is_frozen() -> None:
    """ScanConfig is immutable after creation."""
    config = ScanConfig()

    with pytest.raises(dataclasses.FrozenInstanceError, match="cannot assign to field"):
        config.max_file_size = 1_000_000  # type: ignore[misc]


def test_load_config_returns_defaults() -> None:
    """load_config() returns ScanConfig with default values."""
    config = load_config()

    assert config.max_file_size == 500_000
    assert config.strict_schema is False
    assert ".md" in config.extensions


def test_load_config_scan_section_overrides(tmp_path: Path) -> None:
    """load_config reads [scan] section and overrides defaults."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        '[scan]\nextensions = [".md", ".py"]\nmax_file_size = 1_000_000\n',
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.extensions == frozenset({".md", ".py"})
    assert config.max_file_size == 1_000_000
    # Omitted values keep defaults
    assert config.max_total_size == 5_000_000
    assert config.max_file_count == 100
    assert config.strict_schema is False


def test_load_config_suppress_section(tmp_path: Path) -> None:
    """load_config reads [suppress] section for rule suppression."""
    config = load_config(FIXTURES_DIR / "suppress.toml")

    assert config.suppress_rules == frozenset({"PI-004b", "PI-006"})
    # Scan settings remain defaults
    assert config.max_file_size == 500_000


def test_load_config_scan_settings_fixture() -> None:
    """load_config reads scan_settings.toml fixture correctly."""
    config = load_config(FIXTURES_DIR / "scan_settings.toml")

    assert config.extensions == frozenset({".md", ".py", ".yaml"})
    assert config.max_file_size == 1_000_000
    assert config.suppress_rules == frozenset()


def test_load_config_both_sections(tmp_path: Path) -> None:
    """load_config reads both [scan] and [suppress] sections."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        '[scan]\nmax_file_size = 200_000\nstrict_schema = true\n\n[suppress]\nrules = ["MC-001"]\n',
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.max_file_size == 200_000
    assert config.strict_schema is True
    assert config.suppress_rules == frozenset({"MC-001"})


def test_load_config_missing_file_raises_file_not_found() -> None:
    """load_config raises FileNotFoundError for missing config file."""
    missing = Path("/nonexistent/config.toml")

    with pytest.raises(FileNotFoundError, match="Config file not found"):
        load_config(missing)


def test_load_config_invalid_toml_raises_error(tmp_path: Path) -> None:
    """load_config raises TOMLDecodeError for invalid TOML."""
    bad_file = tmp_path / "bad.toml"
    bad_file.write_text("[invalid\nthis is not valid toml", encoding="utf-8")

    with pytest.raises(tomllib.TOMLDecodeError, match="Expected '\\]'"):
        load_config(bad_file)


def test_load_config_unknown_scan_keys_ignored(tmp_path: Path) -> None:
    """load_config ignores unknown keys in [scan] section."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        "[scan]\nmax_file_size = 300_000\nfuture_option = true\nnew_list = [1, 2]\n",
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.max_file_size == 300_000
    # Unknown keys silently ignored, other defaults preserved
    assert config.max_total_size == 5_000_000


def test_load_config_omitted_values_keep_defaults(tmp_path: Path) -> None:
    """load_config keeps defaults for any omitted config values."""
    config_file = tmp_path / "config.toml"
    config_file.write_text("[scan]\nstrict_schema = true\n", encoding="utf-8")

    config = load_config(config_file)

    assert config.strict_schema is True
    assert config.max_file_size == 500_000
    assert config.max_total_size == 5_000_000
    assert config.max_file_count == 100
    assert ".md" in config.extensions
    assert config.suppress_rules == frozenset()


def test_load_config_empty_file_returns_defaults(tmp_path: Path) -> None:
    """load_config with an empty TOML file returns all defaults."""
    config_file = tmp_path / "empty.toml"
    config_file.write_text("", encoding="utf-8")

    config = load_config(config_file)

    assert config.max_file_size == 500_000
    assert config.suppress_rules == frozenset()


def test_load_config_custom_rule_from_fixture() -> None:
    """load_config reads [rules.*] sections and populates custom_rules."""
    config = load_config(FIXTURES_DIR / "custom_rule.toml")

    assert len(config.custom_rules) == 1
    assert config.custom_rules[0].rule_id == "CUSTOM-001"
    assert config.custom_rules[0].severity == Severity.HIGH
    assert config.custom_rules[0].category == "custom"
    assert config.custom_rules[0].description == "Detects test-marker patterns"


def test_load_config_no_rules_section_leaves_custom_rules_empty(tmp_path: Path) -> None:
    """load_config without [rules] section leaves custom_rules as empty tuple."""
    config_file = tmp_path / "config.toml"
    config_file.write_text("[scan]\nmax_file_size = 100_000\n", encoding="utf-8")

    config = load_config(config_file)

    assert config.custom_rules == ()
