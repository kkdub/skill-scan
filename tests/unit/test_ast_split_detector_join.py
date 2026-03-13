"""Tests for join generator expression, map(chr), and map(str) resolution.

Covers _resolve_join_call() extensions: generator expressions, map(chr, ...),
and map(str, ...) inside ''.join(...). Also includes acceptance scenarios for
the full feature path (f-string conversion, dict subscript, map-chr split).
"""

from __future__ import annotations

import ast

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


# -- File size constraints ----------------------------------------------------


class TestFileSizeConstraints:
    def test_split_detector_under_250_lines(self) -> None:
        import pathlib

        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_split_detector.py"
        count = len(target.read_text().splitlines())
        assert count <= 250, f"_ast_split_detector.py is {count} lines (max 250)"

    def test_split_helpers_under_250_lines(self) -> None:
        import pathlib

        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_split_helpers.py"
        count = len(target.read_text().splitlines())
        assert count <= 250, f"_ast_split_helpers.py is {count} lines (max 250)"

    def test_split_join_helpers_under_250_lines(self) -> None:
        import pathlib

        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_split_join_helpers.py"
        count = len(target.read_text().splitlines())
        assert count <= 250, f"_ast_split_join_helpers.py is {count} lines (max 250)"
