"""File classification — decides which files to scan and which trigger findings.

Pure decision logic. Takes FileEntry metadata and config, returns findings
and the list of files eligible for content scanning. No I/O.
"""

from __future__ import annotations

from pathlib import Path

from skill_scan.config import ScanConfig
from skill_scan.file_checks import (
    check_binary,
    check_file_count,
    check_file_size,
    check_symlink_outside,
    check_total_size,
    check_unknown_extension,
)
from skill_scan.models import FileEntry, Finding

# File-safety rule IDs that mean "do not content-scan this file".
_SKIP_CONTENT_RULES = frozenset({"FS-002", "FS-004", "FS-005"})


def classify_entries(
    entries: list[FileEntry],
    resolved_root: Path,
    config: ScanConfig,
) -> tuple[list[Path], list[Finding]]:
    """Classify file entries into scannable files and file-safety findings.

    Returns:
        (collected_files, fs_findings) where collected_files are eligible
        for content scanning and fs_findings are file-safety issues.
    """
    collected: list[Path] = []
    fs_findings: list[Finding] = []
    total_size = 0
    file_count = 0

    for entry in entries:
        finding = _classify_entry(entry, resolved_root, config)
        total_size += entry.size
        file_count += 1
        if finding:
            fs_findings.append(finding)
            if finding.rule_id not in _SKIP_CONTENT_RULES:
                collected.append(entry.path)
        else:
            collected.append(entry.path)

    for check in (
        check_total_size(total_size, config.max_total_size),
        check_file_count(file_count, config.max_file_count),
    ):
        if check:
            fs_findings.append(check)

    return collected, fs_findings


def _classify_entry(
    entry: FileEntry,
    resolved_root: Path,
    config: ScanConfig,
) -> Finding | None:
    """Classify a single file entry. Returns a Finding or None."""
    # Check if this is an external symlink (classification decision)
    if entry.is_symlink and not entry.resolved_path.is_relative_to(resolved_root):
        return check_symlink_outside(entry.relative_path, entry.resolved_path, resolved_root)

    binary = check_binary(entry.relative_path, entry.suffix)
    if binary:
        return binary

    unknown = check_unknown_extension(entry.relative_path, entry.suffix, config.extensions)
    if unknown:
        return unknown

    return check_file_size(entry.relative_path, entry.size, config.max_file_size)
