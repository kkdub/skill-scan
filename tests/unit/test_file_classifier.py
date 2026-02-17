"""Tests for file_classifier — pure decision logic over FileEntry metadata."""

from __future__ import annotations

from pathlib import Path

from skill_scan.config import ScanConfig
from skill_scan.file_classifier import classify_entries
from skill_scan.models import FileEntry


_ROOT = Path("/project/skill")
_DEFAULT_CONFIG = ScanConfig()


def _entry(
    name: str,
    suffix: str = ".py",
    size: int = 100,
    *,
    is_external_symlink: bool = False,
    resolved_path: Path | None = None,
) -> FileEntry:
    """Build a FileEntry for testing."""
    return FileEntry(
        path=_ROOT / name,
        relative_path=name,
        suffix=suffix,
        size=size,
        is_external_symlink=is_external_symlink,
        resolved_path=resolved_path or _ROOT / name,
    )


class TestClassifyEntriesCollection:
    """Verify which files are collected for content scanning."""

    def test_normal_file_is_collected(self) -> None:
        entries = [_entry("main.py")]
        collected, findings = classify_entries(entries, _ROOT, _DEFAULT_CONFIG)
        assert collected == [_ROOT / "main.py"]
        assert findings == []

    def test_binary_file_is_not_collected(self) -> None:
        entries = [_entry("lib.exe", suffix=".exe")]
        collected, findings = classify_entries(entries, _ROOT, _DEFAULT_CONFIG)
        assert collected == []
        assert len(findings) == 1
        assert findings[0].rule_id == "FS-002"

    def test_external_symlink_is_not_collected(self) -> None:
        entries = [
            _entry(
                "evil-link",
                suffix=".py",
                is_external_symlink=True,
                resolved_path=Path("/etc/passwd"),
            ),
        ]
        collected, findings = classify_entries(entries, _ROOT, _DEFAULT_CONFIG)
        assert collected == []
        assert len(findings) == 1
        assert findings[0].rule_id == "FS-004"

    def test_oversized_file_is_not_collected(self) -> None:
        config = ScanConfig(max_file_size=50)
        entries = [_entry("big.py", size=100)]
        collected, findings = classify_entries(entries, _ROOT, config)
        assert collected == []
        assert any(f.rule_id == "FS-005" for f in findings)

    def test_unknown_extension_is_still_collected(self) -> None:
        """FS-003 files are flagged but still content-scanned."""
        entries = [_entry("data.csv", suffix=".csv")]
        collected, findings = classify_entries(entries, _ROOT, _DEFAULT_CONFIG)
        assert collected == [_ROOT / "data.csv"]
        assert len(findings) == 1
        assert findings[0].rule_id == "FS-003"


class TestClassifyEntriesAggregateChecks:
    """Verify aggregate FS-006 and FS-007 findings."""

    def test_total_size_exceeded_emits_fs006(self) -> None:
        config = ScanConfig(max_total_size=100)
        entries = [_entry("a.py", size=60), _entry("b.py", size=60)]
        _, findings = classify_entries(entries, _ROOT, config)
        assert any(f.rule_id == "FS-006" for f in findings)

    def test_total_size_within_limit_no_fs006(self) -> None:
        entries = [_entry("a.py", size=10)]
        _, findings = classify_entries(entries, _ROOT, _DEFAULT_CONFIG)
        assert not any(f.rule_id == "FS-006" for f in findings)

    def test_file_count_exceeded_emits_fs007(self) -> None:
        config = ScanConfig(max_file_count=2)
        entries = [_entry(f"f{i}.py", size=1) for i in range(3)]
        _, findings = classify_entries(entries, _ROOT, config)
        assert any(f.rule_id == "FS-007" for f in findings)

    def test_file_count_within_limit_no_fs007(self) -> None:
        entries = [_entry("a.py")]
        _, findings = classify_entries(entries, _ROOT, _DEFAULT_CONFIG)
        assert not any(f.rule_id == "FS-007" for f in findings)


class TestClassifyEntriesMixed:
    """Verify correct behavior with mixed entry types."""

    def test_mixed_entries_collect_only_eligible(self) -> None:
        entries = [
            _entry("good.py"),
            _entry("lib.dll", suffix=".dll"),
            _entry("data.csv", suffix=".csv"),
            _entry(
                "escape",
                is_external_symlink=True,
                resolved_path=Path("/tmp/outside"),
            ),
        ]
        collected, findings = classify_entries(entries, _ROOT, _DEFAULT_CONFIG)
        collected_names = {p.name for p in collected}
        assert collected_names == {"good.py", "data.csv"}
        rule_ids = {f.rule_id for f in findings}
        assert "FS-002" in rule_ids  # binary
        assert "FS-003" in rule_ids  # unknown ext
        assert "FS-004" in rule_ids  # external symlink

    def test_empty_entries_returns_empty(self) -> None:
        collected, findings = classify_entries([], _ROOT, _DEFAULT_CONFIG)
        assert collected == []
        assert findings == []
