"""Scan configuration — defaults and loading.

Defines ScanConfig and provides a loader from TOML config files.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypedDict

from skill_scan.models import Rule
from skill_scan.rules.loader import load_rules_from_config

_DEFAULT_EXTENSIONS = frozenset(
    {
        ".md",
        ".txt",
        ".py",
        ".sh",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".jinja2",
    }
)

BINARY_EXTENSIONS = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".wasm",
        ".pyc",
        ".pyo",
        ".bin",
        ".o",
        ".a",
        ".lib",
    }
)


@dataclass(slots=True, frozen=True)
class ScanConfig:
    """Configuration for a scan run."""

    extensions: frozenset[str] = field(default_factory=lambda: _DEFAULT_EXTENSIONS)
    max_file_size: int = 500_000  # 500KB
    max_total_size: int = 5_000_000  # 5MB
    max_file_count: int = 100
    strict_schema: bool = False
    max_workers: int = 0  # 0 = auto-detect; passed to ProcessPoolExecutor
    suppress_rules: frozenset[str] = field(default_factory=frozenset)
    custom_rules: tuple[Rule, ...] = ()


def load_config(path: Path | None = None) -> ScanConfig:
    """Load scan config from a TOML file, or return defaults.

    Args:
        path: Optional path to a TOML config file.

    Returns:
        A ScanConfig instance with settings from the file or defaults.

    Raises:
        FileNotFoundError: If a path is provided but the file does not exist.
        tomllib.TOMLDecodeError: If the file contains invalid TOML.
    """
    if path is None:
        return ScanConfig()

    if not path.exists():
        msg = f"Config file not found: {path}"
        raise FileNotFoundError(msg)

    with path.open("rb") as f:
        data = tomllib.load(f)

    return _build_config(data)


class _ConfigKwargs(TypedDict, total=False):
    extensions: frozenset[str]
    max_file_size: int
    max_total_size: int
    max_file_count: int
    strict_schema: bool
    max_workers: int
    suppress_rules: frozenset[str]
    custom_rules: tuple[Rule, ...]


def _build_config(data: dict[str, object]) -> ScanConfig:
    """Build a ScanConfig from parsed TOML data."""
    kwargs: _ConfigKwargs = {}
    scan_section = data.get("scan", {})

    if isinstance(scan_section, dict):
        _apply_scan_settings(scan_section, kwargs)

    suppress_section = data.get("suppress", {})
    if isinstance(suppress_section, dict):
        rules_list = suppress_section.get("rules", [])
        if isinstance(rules_list, list):
            kwargs["suppress_rules"] = frozenset(str(r) for r in rules_list)

    if "rules" in data:
        custom = load_rules_from_config(data)
        if custom:
            kwargs["custom_rules"] = tuple(custom)

    return ScanConfig(**kwargs)


def _apply_scan_settings(scan_section: dict[str, object], kwargs: _ConfigKwargs) -> None:
    """Extract known [scan] fields into kwargs; unknown keys are ignored."""
    ext_list = scan_section.get("extensions")
    if isinstance(ext_list, list):
        kwargs["extensions"] = frozenset(str(e) for e in ext_list)
    val: object = scan_section.get("max_file_size")
    if isinstance(val, int):
        kwargs["max_file_size"] = val
    val = scan_section.get("max_total_size")
    if isinstance(val, int):
        kwargs["max_total_size"] = val
    val = scan_section.get("max_file_count")
    if isinstance(val, int):
        kwargs["max_file_count"] = val
    val = scan_section.get("max_workers")
    if isinstance(val, int):
        kwargs["max_workers"] = val
    val = scan_section.get("strict_schema")
    if isinstance(val, bool):
        kwargs["strict_schema"] = val
