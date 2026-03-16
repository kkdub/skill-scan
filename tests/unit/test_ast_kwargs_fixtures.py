"""Fixture-based tests for kwargs unpacking detection.

Reads corpus fixtures from tests/fixtures/split_evasion/pos_kwargs_* and
neg_kwargs_*, runs analyze_python() on each, and verifies positive fixtures
produce EXEC-002 findings and negative fixtures produce none.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.ast_analyzer import analyze_python

CORPUS_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion"

_POS_KWARGS_FILES = sorted(CORPUS_DIR.glob("pos_kwargs_*.py"))
_NEG_KWARGS_FILES = sorted(CORPUS_DIR.glob("neg_kwargs_*.py"))


def _fixture_id(p: Path) -> str:
    return p.stem


# ---------------------------------------------------------------------------
# Positive fixtures -- must produce EXEC-002 findings
# ---------------------------------------------------------------------------


class TestKwargsPositiveFixtures:
    """Each positive kwargs fixture must produce at least one EXEC-002 finding."""

    @pytest.mark.parametrize("fixture", _POS_KWARGS_FILES, ids=_fixture_id)
    def test_positive_fixture_detected(self, fixture: Path) -> None:
        source = fixture.read_text(encoding="utf-8")
        findings = analyze_python(source, str(fixture))
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1, f"Expected EXEC-002 in {fixture.name}, got {findings}"

    def test_minimum_positive_count(self) -> None:
        """Guard: at least 4 positive kwargs fixtures must exist."""
        assert len(_POS_KWARGS_FILES) >= 4, f"Need >= 4 pos_kwargs fixtures, found {len(_POS_KWARGS_FILES)}"


# ---------------------------------------------------------------------------
# Negative fixtures -- must produce zero EXEC-002 findings
# ---------------------------------------------------------------------------


class TestKwargsNegativeFixtures:
    """Each negative kwargs fixture must produce zero EXEC-002 findings."""

    @pytest.mark.parametrize("fixture", _NEG_KWARGS_FILES, ids=_fixture_id)
    def test_negative_fixture_no_false_positive(self, fixture: Path) -> None:
        source = fixture.read_text(encoding="utf-8")
        findings = analyze_python(source, str(fixture))
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) == 0, f"False positive in {fixture.name}: {exec_findings}"

    def test_minimum_negative_count(self) -> None:
        """Guard: at least 3 negative kwargs fixtures must exist."""
        assert len(_NEG_KWARGS_FILES) >= 3, f"Need >= 3 neg_kwargs fixtures, found {len(_NEG_KWARGS_FILES)}"
