"""Tests for file safety check functions (FS-002 through FS-007)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.file_checks import (
    check_binary,
    check_file_count,
    check_file_size,
    check_symlink_outside,
    check_total_size,
    check_unknown_extension,
)
from skill_scan.models import Severity


class TestCheckBinary:
    """FS-002: Binary file detection."""

    def test_check_binary_returns_finding_for_exe(self) -> None:
        finding = check_binary("malware.exe", ".exe")
        assert finding is not None
        assert finding.rule_id == "FS-002"
        assert finding.severity == Severity.HIGH
        assert finding.category == "file-safety"

    @pytest.mark.parametrize("suffix", [".dll", ".so", ".dylib", ".wasm", ".pyc"])
    def test_check_binary_returns_finding_for_binary_extensions(self, suffix: str) -> None:
        finding = check_binary(f"file{suffix}", suffix)
        assert finding is not None
        assert finding.rule_id == "FS-002"

    def test_check_binary_returns_none_for_py(self) -> None:
        assert check_binary("script.py", ".py") is None

    def test_check_binary_returns_none_for_md(self) -> None:
        assert check_binary("README.md", ".md") is None


class TestCheckUnknownExtension:
    """FS-003: Unknown file extension detection."""

    def test_check_unknown_returns_finding_for_xyz(self) -> None:
        allowed = frozenset({".py", ".md", ".txt"})
        finding = check_unknown_extension("data.xyz", ".xyz", allowed)
        assert finding is not None
        assert finding.rule_id == "FS-003"
        assert finding.severity == Severity.MEDIUM
        assert finding.category == "file-safety"

    def test_check_unknown_returns_none_for_allowed(self) -> None:
        allowed = frozenset({".py", ".md", ".txt"})
        assert check_unknown_extension("script.py", ".py", allowed) is None

    def test_check_unknown_returns_none_for_no_extension(self) -> None:
        allowed = frozenset({".py", ".md"})
        assert check_unknown_extension("Makefile", "", allowed) is None

    def test_check_unknown_returns_none_for_binary_extension(self) -> None:
        """Binary extensions are caught by FS-002, not FS-003."""
        allowed = frozenset({".py", ".md"})
        assert check_unknown_extension("lib.dll", ".dll", allowed) is None


class TestCheckSymlinkOutside:
    """FS-004: Symlink escape detection."""

    def test_check_symlink_outside_returns_finding(self) -> None:
        skill_root = Path("/project/skill")
        link_target = Path("/etc/passwd")
        finding = check_symlink_outside("evil-link", link_target, skill_root)
        assert finding is not None
        assert finding.rule_id == "FS-004"
        assert finding.severity == Severity.HIGH
        assert finding.category == "file-safety"

    def test_check_symlink_inside_returns_none(self) -> None:
        skill_root = Path("/project/skill")
        link_target = Path("/project/skill/subdir/file.txt")
        assert check_symlink_outside("good-link", link_target, skill_root) is None


class TestCheckFileSize:
    """FS-005: Oversized file detection."""

    def test_check_file_size_returns_finding_when_over_limit(self) -> None:
        finding = check_file_size("large.py", 600_000, 500_000)
        assert finding is not None
        assert finding.rule_id == "FS-005"
        assert finding.severity == Severity.MEDIUM
        assert finding.category == "file-safety"

    def test_check_file_size_returns_none_when_under_limit(self) -> None:
        assert check_file_size("small.py", 400_000, 500_000) is None

    def test_check_file_size_returns_none_when_at_limit(self) -> None:
        assert check_file_size("exact.py", 500_000, 500_000) is None


class TestCheckTotalSize:
    """FS-006: Total skill size detection."""

    def test_check_total_size_returns_finding_when_over(self) -> None:
        finding = check_total_size(6_000_000, 5_000_000)
        assert finding is not None
        assert finding.rule_id == "FS-006"
        assert finding.severity == Severity.MEDIUM
        assert finding.category == "file-safety"

    def test_check_total_size_returns_none_when_under(self) -> None:
        assert check_total_size(4_000_000, 5_000_000) is None

    def test_check_total_size_returns_none_when_at_limit(self) -> None:
        assert check_total_size(5_000_000, 5_000_000) is None


class TestCheckFileCount:
    """FS-007: File count detection."""

    def test_check_file_count_returns_finding_when_over(self) -> None:
        finding = check_file_count(101, 100)
        assert finding is not None
        assert finding.rule_id == "FS-007"
        assert finding.severity == Severity.MEDIUM
        assert finding.category == "file-safety"

    def test_check_file_count_returns_none_when_under(self) -> None:
        assert check_file_count(50, 100) is None

    def test_check_file_count_returns_none_when_at_limit(self) -> None:
        assert check_file_count(100, 100) is None
