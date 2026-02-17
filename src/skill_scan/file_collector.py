"""Filesystem traversal and entry classification for skill scanning.

Walks a skill directory, classifies each entry (binary, symlink, oversized,
unknown extension), and returns the list of files eligible for content scanning
alongside any file-safety findings.
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
from skill_scan.models import Finding

# File-safety rule IDs that mean "do not content-scan this file".
_SKIP_CONTENT_RULES = frozenset({"FS-002", "FS-004", "FS-005"})


def collect_files(skill_dir: Path, config: ScanConfig) -> tuple[list[Path], list[Finding]]:
    """Walk the skill directory and collect scannable files.

    Returns:
        (collected_files, fs_findings) where collected_files are eligible
        for content scanning and fs_findings are file-safety issues.
    """
    collected: list[Path] = []
    fs_findings: list[Finding] = []
    resolved_root = skill_dir.resolve()
    total_size = 0
    file_count = 0
    for file_path in sorted(skill_dir.rglob("*")):
        result = _check_entry(file_path, skill_dir, resolved_root, config)
        if result is None:
            continue
        finding, size = result
        total_size += size
        file_count += 1
        if finding:
            fs_findings.append(finding)
            if finding.rule_id not in _SKIP_CONTENT_RULES:
                collected.append(file_path)
        else:
            collected.append(file_path)

    for check in (
        check_total_size(total_size, config.max_total_size),
        check_file_count(file_count, config.max_file_count),
    ):
        if check:
            fs_findings.append(check)

    return collected, fs_findings


def _check_entry(
    file_path: Path,
    skill_dir: Path,
    resolved_root: Path,
    config: ScanConfig,
) -> tuple[Finding | None, int] | None:
    """Check a single directory entry for file-safety issues.

    Returns None to skip entirely, or (finding_or_None, file_size).
    A non-None finding signals a file-safety issue; the caller decides
    whether to still collect the file for content scanning.
    """
    rel = file_path.relative_to(skill_dir).as_posix()

    if file_path.is_symlink():
        resolved = file_path.resolve()
        if not resolved.is_relative_to(resolved_root):
            return check_symlink_outside(rel, resolved, resolved_root), 0
        # Internal symlink: fall through to binary/extension/size checks

    if not file_path.is_file() or not file_path.resolve().is_relative_to(resolved_root):
        return None

    try:
        size = file_path.stat().st_size
    except OSError:
        return None

    suffix = file_path.suffix
    binary = check_binary(rel, suffix)
    if binary:
        return binary, size

    unknown = check_unknown_extension(rel, suffix, config.extensions)
    if unknown:
        return unknown, size

    size_finding = check_file_size(rel, size, config.max_file_size)
    if size_finding:
        return size_finding, size

    return None, size
