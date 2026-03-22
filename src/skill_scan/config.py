"""Scan configuration — defaults and loading.

Defines ScanConfig and provides a loader from TOML config files.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypedDict, TypeGuard

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
    url_enrichment: bool = False
    url_enrichment_provider: str | None = None
    url_enrichment_settings: tuple[tuple[str, str], ...] = ()


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
    url_enrichment: bool
    url_enrichment_provider: str | None
    url_enrichment_settings: tuple[tuple[str, str], ...]


_INT_SCAN_FIELDS: tuple[
    Literal["max_file_size"],
    Literal["max_total_size"],
    Literal["max_file_count"],
    Literal["max_workers"],
] = (
    "max_file_size",
    "max_total_size",
    "max_file_count",
    "max_workers",
)
_BOOL_SCAN_FIELDS: tuple[Literal["strict_schema"], Literal["url_enrichment"]] = (
    "strict_schema",
    "url_enrichment",
)
_STR_SCAN_FIELDS: tuple[Literal["url_enrichment_provider"]] = ("url_enrichment_provider",)


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


def _is_strict_int(val: object) -> TypeGuard[int]:
    """True when val is int but not bool (bool is a subclass of int)."""
    return isinstance(val, int) and not isinstance(val, bool)


def _apply_scan_settings(scan_section: dict[str, object], kwargs: _ConfigKwargs) -> None:
    """Extract known [scan] fields into kwargs; unknown keys are ignored."""
    _apply_extensions_setting(scan_section, kwargs)
    _apply_int_scan_settings(scan_section, kwargs)
    _apply_bool_scan_settings(scan_section, kwargs)
    _apply_str_scan_settings(scan_section, kwargs)
    _apply_url_enrichment_settings(scan_section, kwargs)


def _apply_extensions_setting(scan_section: dict[str, object], kwargs: _ConfigKwargs) -> None:
    ext_list = scan_section.get("extensions")
    if isinstance(ext_list, list):
        kwargs["extensions"] = frozenset(str(e) for e in ext_list)


def _apply_int_scan_settings(scan_section: dict[str, object], kwargs: _ConfigKwargs) -> None:
    for key in _INT_SCAN_FIELDS:
        value = scan_section.get(key)
        if _is_strict_int(value):
            kwargs[key] = value


def _apply_bool_scan_settings(scan_section: dict[str, object], kwargs: _ConfigKwargs) -> None:
    for key in _BOOL_SCAN_FIELDS:
        value = scan_section.get(key)
        if isinstance(value, bool):
            kwargs[key] = value


def _apply_str_scan_settings(scan_section: dict[str, object], kwargs: _ConfigKwargs) -> None:
    for key in _STR_SCAN_FIELDS:
        value = scan_section.get(key)
        if isinstance(value, str):
            kwargs[key] = value


def _apply_url_enrichment_settings(scan_section: dict[str, object], kwargs: _ConfigKwargs) -> None:
    val = scan_section.get("url_enrichment_settings")
    if isinstance(val, dict):
        kwargs["url_enrichment_settings"] = tuple((str(k), str(v)) for k, v in sorted(val.items()))
