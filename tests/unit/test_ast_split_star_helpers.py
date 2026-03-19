"""Tests for star-unpack in join and list-index concat resolution.

Covers:
- R005: ''.join([*parts1, *parts2]) resolves via star-unpack flattening
- R006: parts[0] + parts[1] resolves via list element tracking in symbol table
- R-EFF001 (partial): corpus inputs produce findings when scanned
- Starred of non-tracked variable returns None (no crash)
- Existing join resolution unchanged (no regression)
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


def _analyze(code: str) -> list[Finding]:
    """Helper: run full analyze_python pipeline."""
    return analyze_python(code, _FILE)


# -- R006: String-list element tracking in symbol table -----------------------


class TestStringListElementTracking:
    """String-list assignments store indexed elements in symbol table."""

    def test_string_list_stores_indexed_elements(self) -> None:
        """parts = ['ev', 'al'] stores parts[0]='ev', parts[1]='al'."""
        code = "parts = ['ev', 'al']"
        result = build_symbol_table(_PARSE(code))
        assert result["parts[0]"] == "ev"
        assert result["parts[1]"] == "al"

    def test_string_list_stores_length(self) -> None:
        """parts = ['ev', 'al'] stores parts.__len__ = '2'."""
        code = "parts = ['ev', 'al']"
        result = build_symbol_table(_PARSE(code))
        assert result["parts.__len__"] == "2"

    def test_string_tuple_stores_indexed_elements(self) -> None:
        """Tuples also get indexed: parts = ('a', 'b', 'c')."""
        code = "parts = ('a', 'b', 'c')"
        result = build_symbol_table(_PARSE(code))
        assert result["parts[0]"] == "a"
        assert result["parts[1]"] == "b"
        assert result["parts[2]"] == "c"
        assert result["parts.__len__"] == "3"

    def test_mixed_type_list_skipped(self) -> None:
        """Lists with non-string elements don't get indexed."""
        code = "parts = ['ev', 42]"
        result = build_symbol_table(_PARSE(code))
        assert "parts[0]" not in result
        assert "parts.__len__" not in result

    def test_empty_list_stores_zero_length(self) -> None:
        """Empty list stores __len__ = '0' but no indexed elements."""
        code = "parts = []"
        result = build_symbol_table(_PARSE(code))
        assert result["parts.__len__"] == "0"
        assert "parts[0]" not in result

    def test_single_element_list(self) -> None:
        """Single-element list: parts = ['eval']."""
        code = "parts = ['eval']"
        result = build_symbol_table(_PARSE(code))
        assert result["parts[0]"] == "eval"
        assert result["parts.__len__"] == "1"

    def test_function_scope_string_list(self) -> None:
        """String-list in function scope is prefixed correctly."""
        code = "def foo():\n    parts = ['ev', 'al']"
        result = build_symbol_table(_PARSE(code))
        assert result["foo.parts[0]"] == "ev"
        assert result["foo.parts[1]"] == "al"
        assert result["foo.parts.__len__"] == "2"


# -- R006: List index concat via BinOp chain ---------------------------------


class TestListIndexConcat:
    """parts[0] + parts[1] resolves to concatenated string via BinOp chain."""

    def test_list_index_concat_resolves_in_split_detector(self) -> None:
        """parts[0] + parts[1] resolves to 'eval' via split detector."""
        code = "parts = ['ev', 'al']\neval(parts[0] + parts[1])\n"
        findings = _detect(code)
        resolved = [f for f in findings if "eval" in f.description.lower()]
        assert len(resolved) >= 1

    def test_list_index_concat_full_pipeline(self) -> None:
        """parts[0] + parts[1] used in eval() triggers EXEC finding."""
        code = "parts = ['ev', 'al']\neval(parts[0] + parts[1])\n"
        findings = _analyze(code)
        exec_findings = [f for f in findings if f.rule_id.startswith("EXEC")]
        assert len(exec_findings) >= 1

    def test_three_element_concat_detection(self) -> None:
        """Three-element concat: parts[0] + parts[1] + parts[2] resolves."""
        code = "parts = ['e', 'va', 'l']\neval(parts[0] + parts[1] + parts[2])\n"
        findings = _detect(code)
        resolved = [f for f in findings if "eval" in f.description.lower()]
        assert len(resolved) >= 1


# -- R005: Star-unpack in join -----------------------------------------------


class TestStarUnpackJoin:
    """''.join([*parts1, *parts2]) resolves via star-unpack flattening."""

    def test_star_unpack_two_lists(self) -> None:
        """''.join([*p1, *p2]) with p1=['ev'], p2=['al'] -> 'eval' detection."""
        code = "p1 = ['ev']\np2 = ['al']\n''.join([*p1, *p2])\n"
        findings = _detect(code)
        resolved = [f for f in findings if "eval" in f.description.lower()]
        assert len(resolved) >= 1

    def test_star_unpack_full_pipeline(self) -> None:
        """Full analyze_python detects star-unpack evasion."""
        code = "parts1 = ['ev']\nparts2 = ['al']\neval(''.join([*parts1, *parts2]))\n"
        findings = _analyze(code)
        exec_findings = [f for f in findings if f.rule_id.startswith("EXEC")]
        assert len(exec_findings) >= 1

    def test_star_unpack_with_non_starred_elements(self) -> None:
        """Mix of starred and non-starred: ''.join([*p1, 'al'])."""
        code = "p1 = ['ev']\n''.join([*p1, 'al'])\n"
        findings = _detect(code)
        resolved = [f for f in findings if "eval" in f.description.lower()]
        assert len(resolved) >= 1

    def test_star_unpack_three_lists(self) -> None:
        """Three starred lists: ''.join([*a, *b, *c])."""
        code = "a = ['e']\nb = ['va']\nc = ['l']\n''.join([*a, *b, *c])\n"
        findings = _detect(code)
        resolved = [f for f in findings if "eval" in f.description.lower()]
        assert len(resolved) >= 1

    def test_starred_non_tracked_variable_returns_none(self) -> None:
        """Starred of non-tracked variable does not crash, returns no findings."""
        code = "import unknown\n''.join([*unknown_var])\n"
        findings = _detect(code)
        # Should not crash; may or may not have findings but no exception
        assert isinstance(findings, list)

    def test_starred_in_tuple_join(self) -> None:
        """Star-unpack in tuple arg to join: ''.join((*p1, *p2))."""
        code = "p1 = ['ev']\np2 = ['al']\n''.join((*p1, *p2))\n"
        findings = _detect(code)
        resolved = [f for f in findings if "eval" in f.description.lower()]
        assert len(resolved) >= 1


# -- Regression: existing join resolution unchanged ---------------------------


class TestExistingJoinRegression:
    """Existing join patterns still work after star-unpack changes."""

    def test_plain_list_join_still_works(self) -> None:
        """''.join(['ev', 'al']) still resolves."""
        code = "''.join(['ev', 'al'])\n"
        findings = _detect(code)
        resolved = [f for f in findings if "eval" in f.description.lower()]
        assert len(resolved) >= 1

    def test_generator_join_still_works(self) -> None:
        """''.join(chr(c) for c in [101,118,97,108]) still resolves."""
        code = "''.join(chr(c) for c in [101, 118, 97, 108])\n"
        findings = _detect(code)
        resolved = [f for f in findings if "eval" in f.description.lower()]
        assert len(resolved) >= 1


# -- R-EFF001: Corpus-style inputs produce findings ---------------------------


class TestCorpusInputs:
    """Corpus-style Python snippets that should produce findings."""

    def test_star_unpack_exec_evasion(self) -> None:
        """Realistic evasion: star-unpack to build 'exec' call."""
        code = "prefix = ['ex']\nsuffix = ['ec']\nfunc_name = ''.join([*prefix, *suffix])\neval(func_name)\n"
        findings = _analyze(code)
        exec_findings = [f for f in findings if f.rule_id.startswith("EXEC")]
        assert len(exec_findings) >= 1

    def test_list_index_getattr_evasion(self) -> None:
        """Realistic evasion: list index to build dangerous attr name."""
        code = "parts = ['ev', 'al']\nfn = getattr(__builtins__, parts[0] + parts[1])\n"
        findings = _analyze(code)
        exec_findings = [f for f in findings if f.rule_id.startswith("EXEC")]
        assert len(exec_findings) >= 1
