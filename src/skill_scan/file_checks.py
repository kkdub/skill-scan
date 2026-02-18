"""File safety checks — pure functions for FS-002 through FS-007.

Each function receives file metadata and returns a Finding or None.
No I/O — all filesystem access happens in scanner.py.
"""

from __future__ import annotations

from pathlib import Path

from skill_scan.config import BINARY_EXTENSIONS
from skill_scan.models import Finding, Severity


def check_binary(file_path: str, suffix: str) -> Finding | None:
    """FS-002: Flag binary files found in the skill directory."""
    if suffix not in BINARY_EXTENSIONS:
        return None
    return Finding(
        rule_id="FS-002",
        severity=Severity.HIGH,
        category="file-safety",
        file=file_path,
        line=None,
        matched_text="",
        description=f"Binary file detected: {file_path}",
        recommendation="Remove binary files or provide source code instead.",
    )


def check_unknown_extension(file_path: str, suffix: str, allowed: frozenset[str]) -> Finding | None:
    """FS-003: Flag files with unrecognised extensions."""
    if suffix == "":
        return None
    if suffix in allowed or suffix in BINARY_EXTENSIONS:
        return None
    return Finding(
        rule_id="FS-003",
        severity=Severity.MEDIUM,
        category="file-safety",
        file=file_path,
        line=None,
        matched_text="",
        description=f"Unknown file extension '{suffix}' in {file_path}",
        recommendation="Verify this file type is expected, or add it to allowed extensions.",
    )


def check_symlink_outside(file_path: str, link_target: Path, skill_root: Path) -> Finding | None:
    """FS-004: Flag symlinks that point outside the skill directory."""
    if link_target.is_relative_to(skill_root):
        return None
    return Finding(
        rule_id="FS-004",
        severity=Severity.HIGH,
        category="file-safety",
        file=file_path,
        line=None,
        matched_text="",
        description=f"Symlink points outside skill directory: {file_path}",
        recommendation="Remove symlinks that reference files outside the skill root.",
    )


def check_file_size(file_path: str, size: int, limit: int) -> Finding | None:
    """FS-005: Flag files exceeding the size limit."""
    if size <= limit:
        return None
    return Finding(
        rule_id="FS-005",
        severity=Severity.MEDIUM,
        category="file-safety",
        file=file_path,
        line=None,
        matched_text="",
        description=f"File exceeds size limit ({size:,} bytes > {limit:,} bytes): {file_path}",
        recommendation="Reduce file size or adjust max_file_size in config.",
    )


def check_total_size(total_size: int, limit: int) -> Finding | None:
    """FS-006: Flag when total skill size exceeds the limit."""
    if total_size <= limit:
        return None
    return Finding(
        rule_id="FS-006",
        severity=Severity.MEDIUM,
        category="file-safety",
        file="<skill>",
        line=None,
        matched_text="",
        description=f"Total skill size exceeds limit ({total_size:,} bytes > {limit:,} bytes)",
        recommendation="Reduce total file size or adjust max_total_size in config.",
    )


def check_file_count(count: int, limit: int) -> Finding | None:
    """FS-007: Flag when the skill contains too many files."""
    if count <= limit:
        return None
    return Finding(
        rule_id="FS-007",
        severity=Severity.MEDIUM,
        category="file-safety",
        file="<skill>",
        line=None,
        matched_text="",
        description=f"File count exceeds limit ({count} > {limit})",
        recommendation="Reduce number of files or adjust max_file_count in config.",
    )
