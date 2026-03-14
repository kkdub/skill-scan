"""Tests for implicit concat verification and string slice resolution.

Covers:
- R001: Implicit string concatenation detected via symbol table
- R002: String slicing resolution in _resolve_subscript_expr
- R-EFF003: Multi-part adjacent literal concat
- R-EFF007: Open-ended slice detection
- R-IMP001: No false positives from ordinary slices
"""

from __future__ import annotations

import ast
import pathlib

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"
_FIXTURE_DIR = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


# -- R001: Implicit concat (symbol table validation) -------------------------


class TestImplicitConcat:
    """Implicit concat ('ev' 'al') merges at parse time; symbol table tracks it."""

    def test_two_part_implicit_concat_detected(self) -> None:
        code = "prefix = 'ev' 'a'\nsuffix = 'l'\nresult = prefix + suffix"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_three_part_implicit_concat_detected(self) -> None:
        """R-EFF003: three-part adjacent literal concat."""
        code = "part = 'sy' 'ste' 'm'\ncmd = part + ''"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "system" in findings[0].matched_text

    def test_safe_implicit_concat_no_finding(self) -> None:
        code = "greeting = 'hello' ' ' 'world'\npath = '/usr' '/local'"
        assert len(_detect(code)) == 0

    def test_implicit_concat_fixture_positive(self) -> None:
        findings = _detect((_FIXTURE_DIR / "pos_implicit_concat.py").read_text())
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(exec_findings) >= 1

    def test_implicit_concat_fixture_negative(self) -> None:
        findings = _detect((_FIXTURE_DIR / "neg_implicit_concat_safe.py").read_text())
        split = [f for f in findings if "split" in f.matched_text or "encoded" in f.matched_text]
        assert len(split) == 0


# -- R002: String slicing resolution -----------------------------------------


class TestSliceResolution:
    """Slice resolution extracts substrings from tracked variables."""

    def test_basic_slice_extracts_eval(self) -> None:
        code = "s = 'xxevalxx'\nname = s[2:6] + ''"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_open_ended_slice_extracts_eval(self) -> None:
        """R-EFF007: open-ended slice with no stop."""
        code = "s = 'xxeval'\nname = s[2:] + ''"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_slice_with_start_only(self) -> None:
        code = "s = 'eval_extra'\nname = s[:4] + ''"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_safe_slice_no_finding(self) -> None:
        """R-IMP001: slicing non-dangerous strings produces no findings."""
        code = "s = 'hello world'\nw = s[:5] + ''"
        assert len(_detect(code)) == 0

    def test_untracked_variable_slice_no_finding(self) -> None:
        """Slicing untracked variables returns None (no false positives)."""
        code = "name = unknown[2:6] + ''"
        assert len(_detect(code)) == 0

    def test_non_constant_bounds_no_finding(self) -> None:
        """Non-Constant slice bounds are rejected."""
        code = "s = 'xxevalxx'\ni = 2\nname = s[i:6] + ''"
        assert len(_detect(code)) == 0

    def test_negative_step_rejected(self) -> None:
        """Negative step slices are rejected to prevent false positives."""
        code = "s = 'lave'\nname = s[::-1] + ''"
        assert len(_detect(code)) == 0

    def test_positive_step_allowed(self) -> None:
        code = "s = 'eval'\nname = s[0:4:1] + ''"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_slice_fixture_pos_eval(self) -> None:
        findings = _detect((_FIXTURE_DIR / "pos_slice_eval.py").read_text())
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_slice_fixture_pos_open_ended(self) -> None:
        findings = _detect((_FIXTURE_DIR / "pos_slice_open_ended.py").read_text())
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_slice_fixture_neg_safe(self) -> None:
        findings = _detect((_FIXTURE_DIR / "neg_slice_safe.py").read_text())
        split = [f for f in findings if "split" in f.matched_text or "encoded" in f.matched_text]
        assert len(split) == 0


# -- E2E acceptance through analyze_python -----------------------------------


class TestSliceAcceptanceE2E:
    """End-to-end acceptance via analyze_python."""

    def test_slice_e2e_analyze_python(self) -> None:
        from skill_scan.ast_analyzer import analyze_python

        source = "s = 'xxevalxx'\nname = s[2:6] + ''"
        findings = analyze_python(source, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
        assert "eval" in exec002[0].matched_text

    def test_implicit_concat_e2e_analyze_python(self) -> None:
        from skill_scan.ast_analyzer import analyze_python

        source = "prefix = 'ev' 'a'\nsuffix = 'l'\nresult = prefix + suffix"
        findings = analyze_python(source, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
        assert "eval" in exec002[0].matched_text
