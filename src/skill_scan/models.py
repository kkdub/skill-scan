"""Data models for skill-scan findings, rules, and scan results.

Pure data definitions — no I/O, no logging, no side effects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(Enum):
    """Overall scan verdict."""

    PASS = "pass"
    FLAG = "flag"
    BLOCK = "block"


@dataclass(slots=True, frozen=True)
class Finding:
    """A single security finding from a scan."""

    rule_id: str
    severity: Severity
    category: str
    file: str
    line: int | None
    matched_text: str
    description: str
    recommendation: str


@dataclass(slots=True, frozen=True)
class Rule:
    """A detection rule with compiled regex patterns."""

    rule_id: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    patterns: tuple[re.Pattern[str], ...]
    exclude_patterns: tuple[re.Pattern[str], ...]
    path_exclude_patterns: tuple[re.Pattern[str], ...] = ()
    confidence: str = "stable"
    match_scope: str = "line"
    exclude_mode: str = "default"


@dataclass(slots=True, frozen=True)
class ScanResult:
    """Aggregated result of a complete scan."""

    findings: tuple[Finding, ...]
    counts: dict[str, int]
    verdict: Verdict
    duration: float
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    degraded_reasons: tuple[str, ...] = ()
    skill_name: str | None = None
    error_message: str | None = None


@dataclass(slots=True, frozen=True)
class FileEntry:
    """Filesystem metadata for a single entry in a skill directory.

    Raw filesystem data only — no classification decisions.
    is_symlink indicates whether path is a symlink (internal or external).
    Classification logic determines if a symlink is external by comparing
    resolved_path to the skill root.
    """

    path: Path
    relative_path: str
    suffix: str
    size: int
    is_symlink: bool
    resolved_path: Path
