"""Tests for scan configuration."""

import dataclasses

import pytest

from skill_scan.config import ScanConfig, load_config


def test_scan_config_has_default_extensions() -> None:
    """ScanConfig defaults include common text file extensions."""
    config = ScanConfig()

    assert ".md" in config.extensions
    assert ".py" in config.extensions
    assert ".txt" in config.extensions
    assert ".sh" in config.extensions
    assert ".yaml" in config.extensions
    assert ".yml" in config.extensions
    assert ".json" in config.extensions
    assert ".toml" in config.extensions


def test_scan_config_has_default_max_file_size() -> None:
    """ScanConfig defaults to 500KB max file size."""
    config = ScanConfig()

    assert config.max_file_size == 500_000


def test_scan_config_has_default_strict_schema() -> None:
    """ScanConfig defaults to strict_schema=False."""
    config = ScanConfig()

    assert config.strict_schema is False


def test_scan_config_is_frozen() -> None:
    """ScanConfig is immutable after creation."""
    config = ScanConfig()

    with pytest.raises(dataclasses.FrozenInstanceError, match="cannot assign to field"):
        config.max_file_size = 1_000_000  # type: ignore[misc]


def test_load_config_returns_scan_config() -> None:
    """load_config() returns a ScanConfig instance."""
    config = load_config()

    assert isinstance(config, ScanConfig)


def test_load_config_returns_defaults() -> None:
    """load_config() returns ScanConfig with default values."""
    config = load_config()

    assert config.max_file_size == 500_000
    assert config.strict_schema is False
    assert ".md" in config.extensions


def test_load_config_with_none_returns_defaults() -> None:
    """load_config(None) returns ScanConfig with default values."""
    config = load_config(None)

    assert config.max_file_size == 500_000
    assert config.strict_schema is False
    assert ".py" in config.extensions
