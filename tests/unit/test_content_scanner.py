"""Tests for content_scanner — file reading, error handling, and size limits."""

from __future__ import annotations

from pathlib import Path

from skill_scan.content_scanner import scan_all_files


class TestScanAllFilesSizeLimit:
    """Defense-in-depth: content scanner enforces FS-005 after reading.

    If stat() failed in the collector, the classifier could not enforce
    the file-size limit. The content scanner re-checks actual content
    size to close this gap.
    """

    def test_oversized_file_emits_fs005_finding(self, tmp_path: Path) -> None:
        """A file larger than max_file_size is rejected with FS-005."""
        big = tmp_path / "big.py"
        big.write_text("x" * 200, encoding="utf-8")

        findings, scanned, skipped = scan_all_files([big], tmp_path, [], max_file_size=100)

        assert len(findings) == 1
        assert findings[0].rule_id == "FS-005"
        assert scanned == 0
        assert skipped == 1

    def test_file_within_limit_is_scanned(self, tmp_path: Path) -> None:
        """A file within max_file_size proceeds to rule matching."""
        ok = tmp_path / "ok.py"
        ok.write_text("print('hi')", encoding="utf-8")

        findings, scanned, skipped = scan_all_files([ok], tmp_path, [], max_file_size=1000)

        assert findings == []
        assert scanned > 0
        assert skipped == 0

    def test_zero_max_file_size_disables_check(self, tmp_path: Path) -> None:
        """max_file_size=0 (default) skips the size guard."""
        big = tmp_path / "big.py"
        big.write_text("x" * 200, encoding="utf-8")

        findings, scanned, skipped = scan_all_files([big], tmp_path, [], max_file_size=0)

        assert findings == []
        assert scanned == 200
        assert skipped == 0
