"""Tests for mixed %-specifier handling, over-provisioning defense, and %% exclusion.

Overflow from test_ast_split_helpers.py (250-line limit).
Covers R008, R009, R-IMP004, R-IMP005, R-IMP006, R-ADV001, R-ADV002.
"""

from __future__ import annotations


from skill_scan._ast_split_helpers import (
    _PERCENT_SPEC_RE,
    _substitute_percent,
)

from tests.unit.test_ast_split_helpers import _detect


# -- R009: Mixed %-specifier matching ----------------------------------------


class TestMixedSpecifiers:
    def test_percent_d_specifier_resolves(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = '%s%d' % (a, b)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_percent_f_specifier_resolves(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = '%f%s' % (a, b)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_percent_x_specifier_resolves(self) -> None:
        findings = _detect("a = 'ex'\nb = 'ec'\nc = '%x%s' % (a, b)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_three_mixed_specifiers_system(self) -> None:
        findings = _detect("a = 'sy'\nb = 'st'\nc = 'em'\nd = '%s%d%r' % (a, b, c)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "system" in findings[0].matched_text

    def test_all_specifier_letters_matched(self) -> None:
        """Regex matches all documented specifier letters."""
        for spec in "sdfrxoegcai":
            assert _PERCENT_SPEC_RE.search(f"%{spec}") is not None

    def test_unknown_specifier_not_matched(self) -> None:
        assert _PERCENT_SPEC_RE.search("%z") is None
        assert _PERCENT_SPEC_RE.search("%q") is None

    def test_single_mixed_specifier_resolves(self) -> None:
        """Single %d with single-arg RHS resolves correctly."""
        findings = _detect("a = 'eval'\nc = '%d' % a")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


# -- R-IMP005: %% exclusion --------------------------------------------------


class TestPercentEscapeExclusion:
    def test_double_percent_not_counted(self) -> None:
        """%%s should not match as a placeholder."""
        assert _PERCENT_SPEC_RE.search("%%s") is None

    def test_double_percent_in_template(self) -> None:
        """Template with %%s literal should not produce findings."""
        assert len(_detect("a = 'eval'\nc = '%%s' % a")) == 0

    def test_mixed_escaped_and_real(self) -> None:
        """%%s followed by real %s: only real one counts."""
        matches = _PERCENT_SPEC_RE.findall("%%s%s")
        assert len(matches) == 1
        assert matches[0] == "%s"


# -- R008/R-ADV001: Over-provisioning defense --------------------------------


class TestOverProvisioningDefense:
    def test_substitute_returns_none_when_over_provisioned(self) -> None:
        result = _substitute_percent("%s", ["a", "b"])
        assert result is None

    def test_substitute_returns_none_three_vals_two_placeholders(self) -> None:
        result = _substitute_percent("%s%d", ["a", "b", "c"])
        assert result is None

    def test_e2e_over_provisioned_no_finding(self) -> None:
        """Over-provisioned %-format must not silently produce output."""
        assert len(_detect("a = 'ev'\nb = 'al'\nc = 'x'\nd = '%s' % (a, b, c)")) == 0

    def test_correctly_provisioned_still_works(self) -> None:
        """R-IMP004: correctly provisioned call unchanged."""
        result = _substitute_percent("%s%s", ["ev", "al"])
        assert result == "eval"

    def test_exact_match_count_works(self) -> None:
        result = _substitute_percent("%s%d%f", ["a", "b", "c"])
        assert result == "abc"


# -- R-IMP006: %s-only regression -------------------------------------------


class TestPercentSRegression:
    def test_percent_s_only_eval_still_detected(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = '%s%s' % (a, b)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_percent_s_only_exec_still_detected(self) -> None:
        findings = _detect("a = 'ex'\nb = 'ec'\nc = '%s%s' % (a, b)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "exec" in findings[0].matched_text

    def test_percent_s_single_arg_still_detected(self) -> None:
        findings = _detect("a = 'eval'\nc = '%s' % a")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"


# -- R-ADV002: Mixed specifier evasion detection ----------------------------


class TestMixedSpecifierEvasionDetection:
    def test_mixed_specifier_import_evasion(self) -> None:
        """Mixed specifiers assembling __import__ must fire EXEC-006."""
        findings = _detect("a = '__im'\nb = 'port__'\nc = '%s%d' % (a, b)")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_mixed_popen_detection(self) -> None:
        findings = _detect("a = 'po'\nb = 'pen'\nc = '%d%s' % (a, b)")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "popen" in findings[0].matched_text
