"""Integration tests for AST + regex engine integration in content_scanner.

Covers: engine integration for .py files, regex-only for non-Python files,
deduplication by (rule_id, line), and AST-only evasion detection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.content_scanner import _apply_rules, _deduplicate, scan_all_files
from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules import load_default_rules
from tests.unit.rule_helpers import filter_by_rule

_ids = filter_by_rule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_rules() -> list[Rule]:
    """Load the full default rule set for integration tests."""
    return load_default_rules()


def _scan(content: str, path: str, rules: list[Rule]) -> list[Finding]:
    """Shorthand for _apply_rules with the given content and path."""
    return _apply_rules(content, path, rules)


# ---------------------------------------------------------------------------
# Python files get both regex AND AST scanning
# ---------------------------------------------------------------------------


class TestPythonFilesGetBothEngines:
    def test_py_file_produces_findings(self, default_rules: list[Rule]) -> None:
        findings = _scan("eval('x')\n", "tool.py", default_rules)
        assert _ids("EXEC-002", findings), "Expected EXEC-002 finding for eval()"

    def test_py_file_ast_evasion_detected(self, default_rules: list[Rule]) -> None:
        code = "getattr(__builtins__, 'ev'+'al')('x')\n"
        findings = _scan(code, "tool.py", default_rules)
        ast_findings = [
            f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006") and "AST" in f.description
        ]
        assert ast_findings, "AST should detect getattr concat evasion"


# ---------------------------------------------------------------------------
# Non-Python files get regex only (AST not attempted)
# ---------------------------------------------------------------------------


class TestNonPythonRegexOnly:
    @pytest.mark.parametrize(
        "path",
        ["README.md", "config.yaml", "data.json", "script.sh", "notes.txt"],
    )
    def test_non_py_no_ast_findings(self, path: str, default_rules: list[Rule]) -> None:
        # eval() in non-Python files should produce regex findings only
        findings = _scan("eval('x')\n", path, default_rules)
        ast_findings = [f for f in findings if "AST" in f.description]
        assert not ast_findings, f"AST should not run on {path}"

    def test_md_file_still_gets_regex_findings(self, default_rules: list[Rule]) -> None:
        findings = _scan("eval('x')\n", "README.md", default_rules)
        exec_findings = _ids("EXEC-002", findings)
        assert exec_findings, "Regex should still detect eval() in .md files"


# ---------------------------------------------------------------------------
# Deduplication: (rule_id, line) -- no duplicates from regex + AST
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_eval_produces_exactly_one_finding(self, default_rules: list[Rule]) -> None:
        """Plain eval() is caught by both regex and AST -- only one should appear."""
        findings = _scan("eval(data)\n", "tool.py", default_rules)
        exec002 = _ids("EXEC-002", findings)
        line1 = [f for f in exec002 if f.line == 1]
        assert len(line1) == 1, f"Expected 1 EXEC-002 on line 1, got {len(line1)}"

    def test_exec_produces_exactly_one_finding(self, default_rules: list[Rule]) -> None:
        findings = _scan("exec('print(1)')\n", "tool.py", default_rules)
        exec002 = _ids("EXEC-002", findings)
        line1 = [f for f in exec002 if f.line == 1]
        assert len(line1) == 1, f"Expected 1 EXEC-002 on line 1, got {len(line1)}"

    def test_regex_finding_takes_priority(self, default_rules: list[Rule]) -> None:
        """When both engines detect the same thing, the regex finding is kept."""
        findings = _scan("eval(data)\n", "tool.py", default_rules)
        exec002 = [f for f in _ids("EXEC-002", findings) if f.line == 1]
        assert len(exec002) == 1
        # Regex findings do NOT contain "AST" in description
        assert "AST" not in exec002[0].description


# ---------------------------------------------------------------------------
# AST-only detections: evasions that regex misses
# ---------------------------------------------------------------------------


class TestAstOnlyDetections:
    def test_getattr_concat_eval_detected(self, default_rules: list[Rule]) -> None:
        code = "getattr(__builtins__, 'ev'+'al')(user_input)\n"
        findings = _scan(code, "tool.py", default_rules)
        relevant = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert relevant, "AST should catch getattr concat evasion"

    def test_string_concat_evasion_detected(self, default_rules: list[Rule]) -> None:
        code = "x = 'ev' + 'al'\n"
        findings = _scan(code, "tool.py", default_rules)
        evasion = [f for f in findings if "evasion" in f.description.lower()]
        assert evasion, "AST should detect string concat evasion"

    def test_chr_evasion_detected(self, default_rules: list[Rule]) -> None:
        code = "x = chr(101)+chr(118)+chr(97)+chr(108)\n"
        findings = _scan(code, "tool.py", default_rules)
        evasion = [f for f in findings if "evasion" in f.description.lower()]
        assert evasion, "AST should detect chr() evasion building 'eval'"


# ---------------------------------------------------------------------------
# _deduplicate unit tests
# ---------------------------------------------------------------------------


class TestDeduplicateHelper:
    def test_no_overlap(self) -> None:
        regex = [_make("R1", 1)]
        ast = [_make("R2", 2)]
        merged = _deduplicate(regex, ast)
        assert len(merged) == 2

    def test_overlap_keeps_regex(self) -> None:
        regex = [_make("R1", 1, desc="regex")]
        ast = [_make("R1", 1, desc="ast")]
        merged = _deduplicate(regex, ast)
        assert len(merged) == 1
        assert merged[0].description == "regex"

    def test_empty_ast(self) -> None:
        regex = [_make("R1", 1)]
        merged = _deduplicate(regex, [])
        assert len(merged) == 1

    def test_empty_regex(self) -> None:
        ast = [_make("R1", 1)]
        merged = _deduplicate([], ast)
        assert len(merged) == 1

    def test_both_empty(self) -> None:
        assert _deduplicate([], []) == []


# ---------------------------------------------------------------------------
# Acceptance scenarios (plan-level)
# ---------------------------------------------------------------------------


class TestAcceptanceScenarios:
    """Plan-level acceptance tests exercising full feature path."""

    def test_ast_catches_evasion_regex_misses(self, tmp_path: Path) -> None:
        """Scan a .py file with getattr concat evasion -- AST catches it."""
        code = "getattr(__builtins__, 'ev'+'al')(user_input)\n"
        py_file = tmp_path / "evil.py"
        py_file.write_text(code, encoding="utf-8")

        rules = load_default_rules()
        findings, _, _ = scan_all_files([py_file], tmp_path, rules)
        relevant = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert relevant, "Should produce finding for getattr concat evasion"
        assert any("evil.py" in f.file for f in relevant)
        assert all(f.line is not None and f.line >= 1 for f in relevant)

    def test_regex_ast_deduplicated_plain_eval(self, tmp_path: Path) -> None:
        """Scan a .py file with plain eval(data) -- exactly one EXEC-002."""
        code = "eval(data)\n"
        py_file = tmp_path / "simple.py"
        py_file.write_text(code, encoding="utf-8")

        rules = load_default_rules()
        findings, _, _ = scan_all_files([py_file], tmp_path, rules)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) == 1, f"Expected exactly 1 EXEC-002, got {len(exec002)}: {exec002}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make(
    rule_id: str,
    line: int,
    desc: str = "test",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.MEDIUM,
        category="test",
        file="test.py",
        line=line,
        matched_text="x",
        description=desc,
        recommendation="fix",
    )
