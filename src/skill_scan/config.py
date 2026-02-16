"""Scan configuration — defaults and loading.

Defines ScanConfig and provides a loader that returns defaults for MVP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

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


def load_config(path: Path | None = None) -> ScanConfig:
    """Load scan config from a TOML file, or return defaults.

    For MVP, always returns defaults. Config file loading deferred.

    Args:
        path: Optional path to a TOML config file (unused for MVP).

    Returns:
        A ScanConfig instance with default settings.
    """
    return ScanConfig()
