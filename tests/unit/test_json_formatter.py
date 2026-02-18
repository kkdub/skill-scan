"""Unit tests for skill_scan.json_formatter JSON output formatting.

Tests format_json() for structure, field presence, determinism, and value correctness.
"""

from __future__ import annotations

import json

from skill_scan.json_formatter import format_json
from skill_scan.models import ScanResult, Severity, Verdict
from tests.unit.formatter_helpers import make_finding


class TestJsonStructure:
    """Tests for top-level JSON schema fields."""

    def test_json_has_all_required_top_level_fields(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.5,
            files_scanned=3,
            skill_name="my-skill",
        )
        data = json.loads(format_json(result))
        expected_keys = {"skill_name", "verdict", "files_scanned", "duration", "counts", "findings"}
        assert set(data.keys()) == expected_keys

    def test_json_output_is_valid_json_with_null_skill_name(self) -> None:
        result = ScanResult(findings=(), counts={}, verdict=Verdict.PASS, duration=0.0)
        data = json.loads(format_json(result))
        assert isinstance(data, dict)
        assert data["skill_name"] is None

    def test_json_scalar_fields_match_input(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
            files_scanned=42,
            skill_name="test-skill",
        )
        data = json.loads(format_json(result))
        assert data["skill_name"] == "test-skill"
        assert data["files_scanned"] == 42


class TestJsonFindings:
    """Tests for finding serialization in JSON output."""

    def test_finding_has_all_eight_fields(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        data = json.loads(format_json(result))
        expected_keys = {
            "rule_id",
            "severity",
            "category",
            "file",
            "line",
            "matched_text",
            "description",
            "recommendation",
        }
        assert set(data["findings"][0].keys()) == expected_keys

    def test_finding_values_match_input(self) -> None:
        finding = make_finding(
            rule_id="PI-001",
            severity=Severity.CRITICAL,
            category="prompt-injection",
            file="SKILL.md",
            line=5,
            matched_text="ignore previous",
            description="Prompt injection detected",
            recommendation="Remove this pattern",
        )
        result = ScanResult(
            findings=(finding,),
            counts={"critical": 1},
            verdict=Verdict.BLOCK,
            duration=0.1,
        )
        data = json.loads(format_json(result))
        f = data["findings"][0]
        assert f["rule_id"] == "PI-001"
        assert f["severity"] == "critical"
        assert f["category"] == "prompt-injection"
        assert f["file"] == "SKILL.md"
        assert f["line"] == 5
        assert f["matched_text"] == "ignore previous"
        assert f["description"] == "Prompt injection detected"
        assert f["recommendation"] == "Remove this pattern"

    def test_finding_line_is_null_when_none(self) -> None:
        finding = make_finding(line=None)
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        data = json.loads(format_json(result))
        assert data["findings"][0]["line"] is None

    def test_multiple_findings_serialized(self) -> None:
        findings = tuple(make_finding(rule_id=f"PI-{i:03d}", file=f"file{i}.md") for i in range(3))
        result = ScanResult(
            findings=findings,
            counts={"medium": 3},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        data = json.loads(format_json(result))
        assert len(data["findings"]) == 3

    def test_empty_findings_produces_empty_list(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
        )
        data = json.loads(format_json(result))
        assert data["findings"] == []


class TestJsonCounts:
    """Tests for severity counts in JSON output."""

    def test_counts_includes_all_five_severity_levels(self) -> None:
        result = ScanResult(
            findings=(),
            counts={},
            verdict=Verdict.PASS,
            duration=0.0,
        )
        data = json.loads(format_json(result))
        expected_levels = {"critical", "high", "medium", "low", "info"}
        assert set(data["counts"].keys()) == expected_levels

    def test_counts_defaults_missing_levels_to_zero(self) -> None:
        result = ScanResult(
            findings=(),
            counts={"medium": 2},
            verdict=Verdict.FLAG,
            duration=0.0,
        )
        data = json.loads(format_json(result))
        assert data["counts"]["critical"] == 0
        assert data["counts"]["high"] == 0
        assert data["counts"]["medium"] == 2
        assert data["counts"]["low"] == 0
        assert data["counts"]["info"] == 0

    def test_counts_preserves_all_provided_values(self) -> None:
        result = ScanResult(
            findings=(),
            counts={"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5},
            verdict=Verdict.BLOCK,
            duration=0.0,
        )
        data = json.loads(format_json(result))
        assert data["counts"] == {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "info": 5,
        }


class TestJsonVerdictAndSeverity:
    """Tests for lowercase verdict and severity values."""

    def test_verdict_is_lowercase_string(self) -> None:
        for verdict in Verdict:
            result = ScanResult(
                findings=(),
                counts={},
                verdict=verdict,
                duration=0.0,
            )
            data = json.loads(format_json(result))
            assert data["verdict"] == verdict.value
            assert data["verdict"] == data["verdict"].lower()

    def test_severity_is_lowercase_string(self) -> None:
        for severity in Severity:
            finding = make_finding(severity=severity)
            result = ScanResult(
                findings=(finding,),
                counts={severity.value: 1},
                verdict=Verdict.FLAG,
                duration=0.0,
            )
            data = json.loads(format_json(result))
            sev_value = data["findings"][0]["severity"]
            assert sev_value == severity.value
            assert sev_value == sev_value.lower()


class TestJsonDeterminism:
    """Tests for deterministic JSON output."""

    def test_output_has_sorted_keys(self) -> None:
        finding = make_finding()
        result = ScanResult(
            findings=(finding,),
            counts={"medium": 1},
            verdict=Verdict.FLAG,
            duration=0.1,
        )
        output = format_json(result)
        data = json.loads(output)
        assert list(data.keys()) == sorted(data.keys())
