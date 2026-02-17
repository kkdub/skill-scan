"""Tests for coverage metadata display in formatted output."""

from __future__ import annotations

from skill_scan.formatters import OutputMode, format_text
from skill_scan.models import ScanResult, Verdict


class TestFormatTextCoverageMetadata:
    """Tests for coverage metadata display in formatted output."""

    def test_header_shows_bytes_scanned(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.1, bytes_scanned=1024)
        output = format_text(result)
        assert "1024 bytes" in output

    def test_header_shows_skipped_files(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.1, files_skipped=2)
        output = format_text(result)
        assert "Skipped: 2 files" in output

    def test_header_shows_degraded_reasons(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.FLAG,
            duration=0.1,
            degraded_reasons=("2 binary files excluded",),
        )
        output = format_text(result)
        assert "Warning: 2 binary files excluded" in output

    def test_quiet_mode_shows_skipped_suffix(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.1, files_skipped=3)
        output = format_text(result, mode=OutputMode.QUIET)
        assert "[3 files skipped]" in output

    def test_quiet_mode_no_suffix_when_no_skips(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.1, files_skipped=0)
        output = format_text(result, mode=OutputMode.QUIET)
        assert "skipped" not in output
