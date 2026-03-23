"""Scanner-level tests for dynamic exec detection (EXEC-006 dedup + e2e).

Tests the _deduplicate AST-preference logic and end-to-end scanner behaviour
for getattr() detection via _apply_rules and analyze_python.
"""

from __future__ import annotations

import pytest

from skill_scan.ast_analyzer import analyze_python
from skill_scan.content_scanner import _apply_rules, _deduplicate
from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules import load_default_rules
from tests.unit.formatter_helpers import make_finding
from tests.unit.rule_helpers import filter_by_rule


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_rules() -> list[Rule]:
    """Load the full default rule set for integration tests."""
    return load_default_rules()


# ---------------------------------------------------------------------------
# Category 1: _deduplicate unit tests (AST-preference logic)
# ---------------------------------------------------------------------------


class TestDeduplicatePrefersAst:
    """After Part B, _deduplicate should prefer AST findings over regex."""

    def test_deduplicate_prefers_ast_over_regex_same_key(self) -> None:
        """When both exist for same (rule_id, line), AST finding wins."""
        regex = [make_finding(rule_id="EXEC-006", line=3, description="regex match")]
        ast = [make_finding(rule_id="EXEC-006", line=3, description="AST detection")]
        merged = _deduplicate(regex, ast)
        exec006 = [f for f in merged if f.rule_id == "EXEC-006" and f.line == 3]
        assert len(exec006) == 1, f"Expected 1 merged finding, got {len(exec006)}"
        assert exec006[0].description == "AST detection"

    def test_deduplicate_keeps_regex_when_no_ast(self) -> None:
        """Regex-only keys are preserved in the output."""
        regex = [make_finding(rule_id="R1", line=1, description="regex only")]
        ast: list[Finding] = []
        merged = _deduplicate(regex, ast)
        assert len(merged) == 1
        assert merged[0].description == "regex only"

    def test_deduplicate_keeps_ast_when_no_regex(self) -> None:
        """AST-only keys are preserved in the output."""
        regex: list[Finding] = []
        ast = [make_finding(rule_id="R2", line=5, description="ast only")]
        merged = _deduplicate(regex, ast)
        assert len(merged) == 1
        assert merged[0].description == "ast only"

    def test_deduplicate_mixed_keys(self) -> None:
        """Some overlapping, some regex-only, some AST-only."""
        regex = [
            make_finding(rule_id="EXEC-006", line=3, description="regex overlap"),
            make_finding(rule_id="R1", line=1, description="regex only"),
        ]
        ast = [
            make_finding(rule_id="EXEC-006", line=3, description="ast overlap"),
            make_finding(rule_id="R2", line=7, description="ast only"),
        ]
        merged = _deduplicate(regex, ast)
        # 3 unique keys: (R1,1), (EXEC-006,3), (R2,7)
        assert len(merged) == 3
        # Overlap key -> AST wins
        overlap = [f for f in merged if f.rule_id == "EXEC-006" and f.line == 3]
        assert len(overlap) == 1
        assert overlap[0].description == "ast overlap"
        # Regex-only preserved
        assert any(f.rule_id == "R1" and f.line == 1 for f in merged)
        # AST-only preserved
        assert any(f.rule_id == "R2" and f.line == 7 for f in merged)

    def test_deduplicate_preserves_order(self) -> None:
        """Output order: regex-order for shared keys replaced by AST, then AST-only."""
        regex = [
            make_finding(rule_id="A", line=1, description="regex-A"),
            make_finding(rule_id="B", line=2, description="regex-B"),
        ]
        ast = [
            make_finding(rule_id="B", line=2, description="ast-B"),
            make_finding(rule_id="C", line=3, description="ast-C"),
        ]
        merged = _deduplicate(regex, ast)
        descriptions = [f.description for f in merged]
        # A stays from regex, B replaced by AST at same position, C appended
        assert descriptions == ["regex-A", "ast-B", "ast-C"]


# ---------------------------------------------------------------------------
# Category 2: Scanner-level end-to-end via _apply_rules
# ---------------------------------------------------------------------------


class TestApplyRulesExec006:
    """End-to-end tests through regex + AST + dedup pipeline."""

    def test_apply_rules_getattr_resolved_var_has_system_in_matched_text(
        self, default_rules: list[Rule]
    ) -> None:
        """Symbol-table resolved 'system' survives dedup in matched_text."""
        code = "import os\nattr = 'system'\ngetattr(os, attr)\n"
        findings = _apply_rules(code, "test.py", default_rules)
        exec006 = filter_by_rule("EXEC-006", findings)
        line3 = [f for f in exec006 if f.line == 3]
        assert len(line3) == 1, f"Expected 1 EXEC-006 on line 3, got {len(line3)}"
        assert "system" in line3[0].matched_text

    def test_apply_rules_getattr_taint_sink_severity_medium(self, default_rules: list[Rule]) -> None:
        """Taint sink on sensitive module -> MEDIUM survives dedup."""
        code = "import os\ndef f(x):\n    getattr(os, x)\n"
        findings = _apply_rules(code, "test.py", default_rules)
        exec006 = filter_by_rule("EXEC-006", findings)
        line3 = [f for f in exec006 if f.line == 3]
        assert len(line3) == 1, f"Expected 1 EXEC-006 on line 3, got {len(line3)}"
        assert line3[0].severity == Severity.MEDIUM

    def test_apply_rules_getattr_non_sensitive_module(self, default_rules: list[Rule]) -> None:
        """getattr on non-sensitive module -- AST produces no finding."""
        code = 'config = object()\ngetattr(config, "debug")\n'
        findings = _apply_rules(code, "test.py", default_rules)
        exec006 = filter_by_rule("EXEC-006", findings)
        # Regex may produce a finding (HIGH); AST produces none for non-sensitive
        # If any EXEC-006 exists it must be HIGH (from regex, since AST skips this)
        for f in exec006:
            assert f.severity == Severity.HIGH

    def test_apply_rules_getattr_literal_system_ast_preferred(self, default_rules: list[Rule]) -> None:
        """getattr(os, 'system') -- AST node-level finding preferred over regex."""
        code = "import os\ngetattr(os, 'system')\n"
        findings = _apply_rules(code, "test.py", default_rules)
        exec006 = filter_by_rule("EXEC-006", findings)
        line2 = [f for f in exec006 if f.line == 2]
        assert len(line2) == 1, f"Expected 1 EXEC-006 on line 2, got {len(line2)}"
        # AST node-level includes 'system' in matched_text
        assert "system" in line2[0].matched_text

    def test_apply_rules_getattr_self_not_flagged_by_ast(self, default_rules: list[Rule]) -> None:
        """getattr(self, ...) -- self is not a sensitive module for AST."""
        code = 'class Foo:\n    def bar(self):\n        getattr(self, "process")\n'
        findings = _apply_rules(code, "test.py", default_rules)
        exec006 = filter_by_rule("EXEC-006", findings)
        if exec006:
            # Any finding must come from regex (not AST), so no 'AST' in description
            for f in exec006:
                assert "AST" not in f.description or "Dynamic indirection" in f.description


# ---------------------------------------------------------------------------
# Category 3: Acceptance scenario tests (analyze_python level)
# ---------------------------------------------------------------------------


class TestAcceptanceAnalyzePython:
    """Full Part A + Part B feature path at analyze_python level."""

    def test_acceptance_symbol_table_resolution(self) -> None:
        """Variable resolves to 'system' -> EXEC-006 HIGH with system in text."""
        code = "import os\nattr = 'system'\ngetattr(os, attr)\n"
        findings = [f for f in analyze_python(code, "test.py") if f.rule_id == "EXEC-006"]
        high = [f for f in findings if f.severity == Severity.HIGH]
        matched = [f for f in high if "system" in (f.matched_text or "")]
        assert len(matched) == 1

    def test_acceptance_taint_sink(self) -> None:
        """Unresolvable variable on sensitive module -> EXEC-006 MEDIUM."""
        code = "import os\ndef f(x):\n    getattr(os, x)\n"
        findings = [f for f in analyze_python(code, "test.py") if f.rule_id == "EXEC-006"]
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) == 1

    def test_acceptance_no_taint_on_non_sensitive(self) -> None:
        """getattr on non-sensitive module -> no EXEC-006."""
        code = "def f(x):\n    getattr(config, x)\n"
        findings = [f for f in analyze_python(code, "test.py") if f.rule_id == "EXEC-006"]
        assert len(findings) == 0

    def test_acceptance_scanner_ast_precision_survives_dedup(self, default_rules: list[Rule]) -> None:
        """Through _apply_rules: resolved 'system' in matched_text after dedup."""
        code = "import os\nattr = 'system'\ngetattr(os, attr)\n"
        findings = _apply_rules(code, "test.py", default_rules)
        exec006 = filter_by_rule("EXEC-006", findings)
        line3 = [f for f in exec006 if f.line == 3]
        assert len(line3) == 1
        assert "system" in line3[0].matched_text

    def test_acceptance_scanner_taint_shows_medium(self, default_rules: list[Rule]) -> None:
        """Through _apply_rules: taint sink produces MEDIUM after dedup."""
        code = "import os\ndef f(x):\n    getattr(os, x)\n"
        findings = _apply_rules(code, "test.py", default_rules)
        exec006 = filter_by_rule("EXEC-006", findings)
        line3 = [f for f in exec006 if f.line == 3]
        assert len(line3) == 1
        assert line3[0].severity == Severity.MEDIUM
