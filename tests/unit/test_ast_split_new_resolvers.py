"""Tests for new split-evasion resolvers: format kwargs, format_map, reversal.

Covers R001 (format keyword args), R002 (format_map), R003 (string reversal),
and corpus red-team verification for the three corresponding evasion vectors.
"""

from __future__ import annotations

import ast
import pathlib
import unittest

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


# -- R001: str.format() keyword arg evasion -----------------------------------


class TestFormatKeywordArgs:
    def test_format_keyword_eval(self) -> None:
        """R001: '{prefix}{suffix}'.format(prefix='ev', suffix='al') -> 'eval'."""
        findings = _detect("result = '{prefix}{suffix}'.format(prefix='ev', suffix='al')")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_format_single_keyword_eval(self) -> None:
        findings = _detect("result = '{name}'.format(name='eval')")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_format_keyword_with_tracked_var(self) -> None:
        findings = _detect("x = 'ev'\nresult = '{a}{b}'.format(a=x, b='al')")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_format_kwargs_splat_rejected(self) -> None:
        """**kwargs unpacking (kw.arg is None) must be rejected."""
        assert len(_detect("d = {'name': 'eval'}\nresult = '{name}'.format(**d)")) == 0

    def test_format_mixed_positional_keyword_rejected(self) -> None:
        """Mixed positional + keyword in one template is rejected by Python too."""
        assert len(_detect("result = '{0}{name}'.format('ev', name='al')")) == 0

    def test_format_keyword_safe_no_finding(self) -> None:
        assert len(_detect("result = '{greeting}'.format(greeting='hello')")) == 0


# -- R002: format_map evasion -------------------------------------------------


class TestFormatMapCall:
    def test_format_map_inline_dict(self) -> None:
        """format_map with inline dict resolves."""
        code = "result = '{a}{b}'.format_map({'a': 'ev', 'b': 'al'})"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].matched_text

    def test_format_map_tracked_variable_dict(self) -> None:
        """format_map with tracked variable dict resolves (corpus pattern)."""
        code = "template = '{a}{b}'\nparts = {'a': 'ev', 'b': 'al'}\nname = template.format_map(parts)"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_format_map_safe_no_finding(self) -> None:
        code = "result = '{x}'.format_map({'x': 'hello'})"
        assert len(_detect(code)) == 0

    def test_format_map_no_args_rejected(self) -> None:
        assert len(_detect("result = '{a}'.format_map()")) == 0

    def test_format_map_multiple_args_rejected(self) -> None:
        assert len(_detect("result = '{a}'.format_map({'a': 'ev'}, extra)")) == 0


# -- R003: String reversal via [::-1] -----------------------------------------


class TestStringReversal:
    def test_reverse_eval(self) -> None:
        """s[::-1] resolves 'lave' to 'eval'."""
        findings = _detect("s = 'lave'\nresult = s[::-1]")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_reverse_exec(self) -> None:
        findings = _detect("s = 'cexe'\nresult = s[::-1]")
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_reverse_step_zero_rejected(self) -> None:
        """step=0 is invalid in Python and must be rejected."""
        assert len(_detect("s = 'eval'\nresult = s[::0]")) == 0

    def test_reverse_safe_no_finding(self) -> None:
        assert len(_detect("s = 'olleh'\nresult = s[::-1]")) == 0

    def test_reverse_corpus_pattern(self) -> None:
        """Corpus: backward = 'lave'; name = backward[::-1]; globals()[name](...)."""
        code = "backward = 'lave'\nname = backward[::-1]\nglobals()[name](\"print('pwned')\")\n"
        findings = analyze_python(code, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1


# -- E2E acceptance tests --------------------------------------------------


class TestAcceptanceScenariosNewResolvers:
    def test_format_keywords_e2e_analyze_python(self) -> None:
        """R001: str.format() keyword args detected end-to-end."""
        source = "name = '{prefix}{suffix}'.format(prefix='ev', suffix='al')\nglobals()[name]('x')"
        findings = analyze_python(source, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_format_map_e2e_analyze_python(self) -> None:
        """R002: format_map detected end-to-end."""
        source = "template = '{a}{b}'\nparts = {'a': 'ev', 'b': 'al'}\nname = template.format_map(parts)\nglobals()[name]('x')"
        findings = analyze_python(source, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_reverse_e2e_analyze_python(self) -> None:
        """R003: string reversal detected end-to-end."""
        source = "backward = 'lave'\nname = backward[::-1]\nglobals()[name]('x')"
        findings = analyze_python(source, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1


# -- Corpus red-team verification (Part a) ------------------------------------


class TestCorpusRedTeam:
    _SPLIT_DIR = (
        pathlib.Path(__file__).resolve().parent.parent.parent
        / "corpus"
        / "red-team"
        / "2026-03-17-full"
        / "split-kwargs-evasion"
    )
    _EXEC_DIR = (
        pathlib.Path(__file__).resolve().parent.parent.parent
        / "corpus"
        / "red-team"
        / "2026-03-17-full"
        / "exec-evasion"
    )

    def test_corpus_split_format_keywords(self) -> None:
        """Corpus split_format_keywords.py produces EXEC-002 finding."""
        code = (self._SPLIT_DIR / "split_format_keywords.py").read_text()
        findings = analyze_python(code, "split_format_keywords.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_corpus_format_map_evasion(self) -> None:
        """Corpus format_map_evasion.py produces EXEC-002 finding."""
        code = (self._EXEC_DIR / "format_map_evasion.py").read_text()
        findings = analyze_python(code, "format_map_evasion.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_corpus_split_reverse(self) -> None:
        """Corpus split_reverse.py produces EXEC-002 finding."""
        code = (self._SPLIT_DIR / "split_reverse.py").read_text()
        findings = analyze_python(code, "split_reverse.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1


class TestLookupStrDictScopePriority(unittest.TestCase):
    """Scoped entries should shadow unscoped in _lookup_str_dict."""

    def test_scoped_shadows_unscoped(self) -> None:
        """Function-local dict binding shadows module-level for same key."""
        from skill_scan._ast_split_resolve import _lookup_str_dict

        symbol_table = {
            "parts[a]": "module_val",
            "func.parts[a]": "local_val",
        }
        result = _lookup_str_dict("parts", symbol_table, "func")
        assert result is not None
        assert result["a"] == "local_val"

    def test_scoped_excludes_unscoped_keys(self) -> None:
        """When scoped entries exist, unscoped keys must not leak in."""
        from skill_scan._ast_split_resolve import _lookup_str_dict

        symbol_table = {
            "parts[a]": "module_a",
            "parts[b]": "module_b",
            "func.parts[a]": "local_a",
        }
        result = _lookup_str_dict("parts", symbol_table, "func")
        assert result is not None
        assert result == {"a": "local_a"}
        assert "b" not in result

    def test_falls_back_to_unscoped_when_no_scoped(self) -> None:
        """When no scoped entries exist, unscoped entries are returned."""
        from skill_scan._ast_split_resolve import _lookup_str_dict

        symbol_table = {
            "parts[x]": "val_x",
            "parts[y]": "val_y",
        }
        result = _lookup_str_dict("parts", symbol_table, "func")
        assert result is not None
        assert result == {"x": "val_x", "y": "val_y"}
