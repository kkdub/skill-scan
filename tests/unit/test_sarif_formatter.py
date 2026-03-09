"""Unit tests for skill_scan.sarif_formatter SARIF 2.1.0 output formatting.

Tests format_sarif() for structure, severity mapping, rule metadata,
locations, empty inputs, determinism, and public API.
"""

from __future__ import annotations

import json

import skill_scan
from skill_scan.models import Finding, ScanResult, Severity, Verdict
from skill_scan.sarif_formatter import _severity_to_level, format_sarif
from tests.unit.formatter_helpers import make_finding


def _make_result(
    findings: tuple[Finding, ...] = (),
    counts: dict[str, int] | None = None,
    verdict: Verdict = Verdict.PASS,
    duration: float = 0.0,
    files_scanned: int = 0,
    skill_name: str | None = None,
) -> ScanResult:
    return ScanResult(
        findings=findings,
        counts=counts if counts is not None else {},
        verdict=verdict,
        duration=duration,
        files_scanned=files_scanned,
        skill_name=skill_name,
    )


class TestSarifStructure:
    """Tests for SARIF 2.1.0 top-level structure."""

    def test_sarif_version_is_2_1_0(self) -> None:
        finding = make_finding()
        result = _make_result(findings=(finding,), counts={"medium": 1}, verdict=Verdict.FLAG)
        data = json.loads(format_sarif(result))
        assert data["version"] == "2.1.0"

    def test_sarif_schema_contains_sarif_schema_2_1_0(self) -> None:
        result = _make_result()
        data = json.loads(format_sarif(result))
        assert "sarif-schema-2.1.0" in data["$schema"]

    def test_sarif_runs_is_list_of_length_1(self) -> None:
        result = _make_result()
        data = json.loads(format_sarif(result))
        assert isinstance(data["runs"], list)
        assert len(data["runs"]) == 1

    def test_sarif_tool_driver_name_is_skill_scan(self) -> None:
        result = _make_result()
        data = json.loads(format_sarif(result))
        assert data["runs"][0]["tool"]["driver"]["name"] == "skill-scan"


class TestSarifSeverityMapping:
    """Tests for _severity_to_level private helper — all five severity levels."""

    def test_critical_maps_to_error(self) -> None:
        assert _severity_to_level(Severity.CRITICAL) == "error"

    def test_high_maps_to_error(self) -> None:
        assert _severity_to_level(Severity.HIGH) == "error"

    def test_medium_maps_to_warning(self) -> None:
        assert _severity_to_level(Severity.MEDIUM) == "warning"

    def test_low_maps_to_note(self) -> None:
        assert _severity_to_level(Severity.LOW) == "note"

    def test_info_maps_to_note(self) -> None:
        assert _severity_to_level(Severity.INFO) == "note"


class TestSarifRuleMetadata:
    """Tests for tool.driver.rules generation."""

    def test_rule_has_required_fields(self) -> None:
        finding = make_finding(rule_id="PI-001", description="desc", recommendation="fix it")
        result = _make_result(findings=(finding,), counts={"medium": 1}, verdict=Verdict.FLAG)
        data = json.loads(format_sarif(result))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "PI-001"
        assert rule["shortDescription"]["text"] == "desc"
        assert rule["fullDescription"]["text"] == "fix it"

    def test_rules_are_deduplicated(self) -> None:
        f1 = make_finding(rule_id="PI-001", file="a.md")
        f2 = make_finding(rule_id="PI-001", file="b.md")
        result = _make_result(findings=(f1, f2), counts={"medium": 2}, verdict=Verdict.FLAG)
        data = json.loads(format_sarif(result))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "PI-001"


class TestSarifLocations:
    """Tests for finding location serialization."""

    def test_finding_with_line_number_has_region(self) -> None:
        finding = make_finding(file="prompt.md", line=42)
        result = _make_result(findings=(finding,), counts={"medium": 1}, verdict=Verdict.FLAG)
        data = json.loads(format_sarif(result))
        physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert physical["region"]["startLine"] == 42

    def test_finding_without_line_number_has_no_region(self) -> None:
        finding = make_finding(file="prompt.md", line=None)
        result = _make_result(findings=(finding,), counts={"medium": 1}, verdict=Verdict.FLAG)
        data = json.loads(format_sarif(result))
        physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "prompt.md"
        assert "region" not in physical


class TestSarifEmptyFindings:
    """Tests for format_sarif with no findings."""

    def test_empty_findings_produces_empty_results(self) -> None:
        result = _make_result()
        data = json.loads(format_sarif(result))
        assert data["runs"][0]["results"] == []

    def test_empty_findings_produces_empty_rules(self) -> None:
        result = _make_result()
        data = json.loads(format_sarif(result))
        assert data["runs"][0]["tool"]["driver"]["rules"] == []


class TestSarifDeterminism:
    """Tests for deterministic SARIF output."""

    def test_format_sarif_is_deterministic(self) -> None:
        finding = make_finding()
        result = _make_result(findings=(finding,), counts={"medium": 1}, verdict=Verdict.FLAG)
        assert format_sarif(result) == format_sarif(result)


class TestSarifPublicAPI:
    """Tests for public API export."""

    def test_format_sarif_in_all(self) -> None:
        assert "format_sarif" in skill_scan.__all__
