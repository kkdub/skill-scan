"""Tests for public API exports from skill_scan package."""

from __future__ import annotations


class TestPublicAPIImports:
    """Tests for public API exports from skill_scan package."""

    def test_public_api_exports_all_required_names(self) -> None:
        from skill_scan import (
            Finding,
            OutputMode,
            Rule,
            ScanResult,
            Severity,
            Verdict,
            scan,
        )

        assert all(
            x is not None
            for x in (
                Finding,
                OutputMode,
                Rule,
                ScanResult,
                Severity,
                Verdict,
                scan,
            )
        )
