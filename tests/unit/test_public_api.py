"""Tests for public API exports from skill_scan package."""

from __future__ import annotations

import skill_scan


class TestPublicAPIImports:
    """Tests for public API exports from skill_scan package."""

    def test_public_api_exports_all_required_names(self) -> None:
        expected = {
            "Finding",
            "OutputMode",
            "Rule",
            "ScanResult",
            "Severity",
            "Verdict",
            "format_json",
            "format_sarif",
            "scan",
        }
        actual = set(skill_scan.__all__)
        assert expected == actual, f"Missing: {expected - actual}, Extra: {actual - expected}"
        for name in expected:
            assert hasattr(skill_scan, name), f"{name} in __all__ but not importable"
