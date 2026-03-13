"""Tests for join generator expression, map(chr), and map(str) resolution.

Covers _resolve_join_call() extensions: generator expressions, map(chr, ...),
and map(str, ...) inside ''.join(...). Also includes acceptance scenarios for
the full feature path (f-string conversion, dict subscript, map-chr split).
"""

from __future__ import annotations

import ast

import pytest

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


# -- R005: Generator expression join -----------------------------------------


class TestGeneratorJoin:
    def test_identity_generator_produces_exec002(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = ''.join(p for p in [a, b])")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_literal_elements_in_generator(self) -> None:
        findings = _detect("c = ''.join(p for p in ['ev', 'al'])")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_generator_with_tuple_iter(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = ''.join(p for p in (a, b))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_generator_safe_pattern_no_finding(self) -> None:
        assert len(_detect("''.join(p for p in ['hello', 'world'])")) == 0

    def test_generator_non_identity_no_resolve(self) -> None:
        """Generator with transform (e.g. p.upper()) should not resolve."""
        code = "a = 'ev'\nb = 'al'\nc = ''.join(p.upper() for p in [a, b])"
        assert len(_detect(code)) == 0

    def test_generator_with_filter_no_resolve(self) -> None:
        """Generator with if-clause should not resolve."""
        code = "a = 'ev'\nb = 'al'\nc = ''.join(p for p in [a, b] if p)"
        assert len(_detect(code)) == 0

    def test_generator_multiple_fors_no_resolve(self) -> None:
        """Nested generators should not resolve."""
        code = "''.join(a for a in ['ev'] for b in ['al'])"
        assert len(_detect(code)) == 0


# -- R006: map(chr/str) join -------------------------------------------------


class TestMapChrJoin:
    def test_map_chr_ints_produces_exec002(self) -> None:
        findings = _detect("payload = ''.join(map(chr, [101, 118, 97, 108]))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_map_chr_tuple_produces_exec002(self) -> None:
        findings = _detect("payload = ''.join(map(chr, (101, 118, 97, 108)))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_map_chr_safe_ints_no_finding(self) -> None:
        assert len(_detect("''.join(map(chr, [104, 101, 108, 108, 111]))")) == 0

    def test_map_chr_exec006_import(self) -> None:
        """map(chr) building __import__ should produce EXEC-006."""
        ints = [ord(c) for c in "__import__"]
        code = f"payload = ''.join(map(chr, {ints!r}))"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"


class TestMapStrJoin:
    def test_map_str_strings_produces_exec002(self) -> None:
        findings = _detect("payload = ''.join(map(str, ['ev', 'al']))")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_map_str_safe_strings_no_finding(self) -> None:
        assert len(_detect("''.join(map(str, ['hello', 'world']))")) == 0

    def test_map_other_function_no_resolve(self) -> None:
        """map(len, ...) and other non-chr/str functions should not resolve."""
        assert len(_detect("''.join(map(len, [[1], [2]]))")) == 0

    def test_map_non_list_arg_no_resolve(self) -> None:
        """map(chr, some_var) should not resolve when iterable is not literal."""
        assert len(_detect("x = [101]\n''.join(map(chr, x))")) == 0


# -- Acceptance scenarios (full feature path) ---------------------------------


class TestAcceptanceScenarios:
    def test_fstring_conversion_flag_exec002(self) -> None:
        """F-string with conversion flag assembles dangerous name and triggers EXEC-002."""
        code = "x = 'eval'\nexec(f'{x!r}'.strip(\"'\"))"
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_dict_subscript_evasion(self) -> None:
        """Dict subscript evasion resolves through symbol table to EXEC-002 or EXEC-006."""
        code = "d = {'a': 'ev', 'b': 'al'}\nresult = d['a'] + d['b']"
        findings = analyze_python(code, _FILE)
        relevant = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(relevant) >= 1

    def test_map_chr_join_split_reconstruction(self) -> None:
        """map(chr, ...) join assembles dangerous payload via split reconstruction."""
        code = "payload = ''.join(map(chr, [101, 118, 97, 108]))"
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
        assert any(
            "split" in f.description.lower() or "reassembled" in f.description.lower() for f in exec002
        )


# -- R009/R-EFF001/R-EFF002: List-index subscript resolution -----------------


class TestListIndexSubscriptDetection:
    """Split detector resolves integer-index subscripts to dangerous names (R009)."""

    def test_list_index_concat_produces_exec002(self) -> None:
        """parts[0] + parts[1] -> 'eval' triggers EXEC-002 (R-EFF001)."""
        code = "parts = {}\nparts[0] = 'ev'\nparts[1] = 'al'\nx = parts[0] + parts[1]"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_list_index_mutate_produces_exec002(self) -> None:
        """items[0] = 'ex'; items[1] = 'ec' -> exec triggers EXEC-002 (R-EFF002)."""
        code = "items = {}\nitems[0] = 'ex'\nitems[1] = 'ec'\nx = items[0] + items[1]"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_list_index_fstring_produces_exec002(self) -> None:
        """f'{parts[0]}{parts[1]}' -> 'eval' triggers EXEC-002."""
        code = "parts = {}\nparts[0] = 'ev'\nparts[1] = 'al'\nresult = f'{parts[0]}{parts[1]}'"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_list_index_safe_no_finding(self) -> None:
        """Non-dangerous list-index concat produces no finding."""
        code = "parts = {}\nparts[0] = 'hell'\nparts[1] = 'o'\nx = parts[0] + parts[1]"
        assert len(_detect(code)) == 0

    def test_string_key_still_works(self) -> None:
        """String-key dict subscript detection unchanged (R-IMP001 regression)."""
        code = "d = {'a': 'ev', 'b': 'al'}\nresult = d['a'] + d['b']"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"


# -- File size constraints ----------------------------------------------------


class TestFileSizeConstraints:
    _SPLIT_FILES = (
        "_ast_split_detector.py",
        "_ast_split_helpers.py",
        "_ast_split_join_helpers.py",
        "_ast_split_resolve.py",
    )

    @pytest.mark.parametrize("filename", _SPLIT_FILES)
    def test_split_module_under_250_lines(self, filename: str) -> None:
        import pathlib

        target = pathlib.Path(__file__).resolve().parent.parent.parent / "src" / "skill_scan" / filename
        count = len(target.read_text().splitlines())
        assert count <= 250, f"{filename} is {count} lines (max 250)"


# -- R010: Class self.attr resolution -----------------------------------------


class TestClassSelfAttrResolution:
    def test_self_attr_fstring_produces_exec002(self) -> None:
        code = 'class C:\n  def f(self):\n    self.cmd="eval"\n  def g(self):\n    x=f"{self.cmd}"'
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_cross_method_binop_produces_exec002(self) -> None:
        code = "class E:\n  def a(self):\n    self.x='ev'\n  def b(self):\n    self.y='al'\n  def c(self):\n    r=self.x+self.y"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_self_attr_format_call_produces_exec002(self) -> None:
        code = "class C:\n  def f(self):\n    self.a='ev'\n    self.b='al'\n  def g(self):\n    r='{}{}'.format(self.a,self.b)"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_safe_self_attr_no_finding(self) -> None:
        code = "class C:\n  def f(self):\n    self.x='hello'\n  def g(self):\n    r=f'{self.x}'"
        assert len(_detect(code)) == 0


# -- Acceptance scenarios (plan-level full path) -------------------------------


class TestPlanAcceptance:
    def test_list_index_evasion_e2e(self) -> None:
        code = "parts=['ev','al']\neval(parts[0]+parts[1])"
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
        assert any("eval" in f.matched_text for f in exec002)

    def test_global_overwrite_evasion_e2e(self) -> None:
        code = "x='safe'\ndef f():\n  global x\n  x='exec'\nf()\nexec(x)"
        findings = analyze_python(code, _FILE)
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) >= 1

    def test_cross_method_class_attr_evasion_e2e(self) -> None:
        code = "class E:\n  def build(self):\n    self.x='ev'\n  def setup(self):\n    self.y='al'\n  def run(self):\n    r=self.x+self.y"
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
        assert any("eval" in f.matched_text for f in exec002)
