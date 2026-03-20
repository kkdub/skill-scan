"""Tests for _ast_split_map_resolver -- map(chr/str/lambda) resolution.

Covers _resolve_map_join with direct chr/str, lambda c: chr(c),
and tracked int-list variable resolution via int_list_table.
"""

from __future__ import annotations

import ast
from pathlib import Path


from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_comprehension import _collect_int_list_assigns
from skill_scan._ast_split_map_resolver import _is_lambda_chr, _resolve_map_join
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_FILE = "test.py"


def _make_map_call(code: str) -> ast.Call:
    """Extract the map(...) Call node from a join expression."""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "map":
            return node
    msg = f"No map() call found in: {code}"
    raise ValueError(msg)


def _detect(code: str) -> list[Finding]:
    """Parse code, build tables, run split detector with int_list_table."""
    tree = ast.parse(code)
    st = build_symbol_table(tree)
    il = _collect_int_list_assigns(tree)
    from skill_scan._ast_imports import build_alias_map

    am = build_alias_map(tree)
    return detect_split_evasion(tree, _FILE, am, st, int_list_table=il)


# -- _is_lambda_chr -----------------------------------------------------------


class TestIsLambdaChr:
    def test_simple_lambda_chr(self) -> None:
        tree = ast.parse("lambda c: chr(c)")
        lam = next(n for n in ast.walk(tree) if isinstance(n, ast.Lambda))
        assert _is_lambda_chr(lam) is True

    def test_different_param_name(self) -> None:
        tree = ast.parse("lambda x: chr(x)")
        lam = next(n for n in ast.walk(tree) if isinstance(n, ast.Lambda))
        assert _is_lambda_chr(lam) is True

    def test_lambda_not_chr(self) -> None:
        tree = ast.parse("lambda c: ord(c)")
        lam = next(n for n in ast.walk(tree) if isinstance(n, ast.Lambda))
        assert _is_lambda_chr(lam) is False

    def test_lambda_wrong_arg(self) -> None:
        """Lambda body calls chr but with wrong argument name."""
        tree = ast.parse("lambda c: chr(x)")
        lam = next(n for n in ast.walk(tree) if isinstance(n, ast.Lambda))
        assert _is_lambda_chr(lam) is False

    def test_lambda_multi_args(self) -> None:
        tree = ast.parse("lambda a, b: chr(a)")
        lam = next(n for n in ast.walk(tree) if isinstance(n, ast.Lambda))
        assert _is_lambda_chr(lam) is False

    def test_lambda_with_vararg(self) -> None:
        tree = ast.parse("lambda *c: chr(c)")
        lam = next(n for n in ast.walk(tree) if isinstance(n, ast.Lambda))
        assert _is_lambda_chr(lam) is False

    def test_lambda_body_not_call(self) -> None:
        tree = ast.parse("lambda c: c + 1")
        lam = next(n for n in ast.walk(tree) if isinstance(n, ast.Lambda))
        assert _is_lambda_chr(lam) is False


# -- _resolve_map_join with lambda -------------------------------------------


class TestResolveMapJoinLambda:
    def test_lambda_chr_literal_list(self) -> None:
        code = "''.join(map(lambda c: chr(c), [101, 118, 97, 108]))"
        call = _make_map_call(code)
        result = _resolve_map_join(call, "", {})
        assert result == "eval"

    def test_lambda_chr_with_separator(self) -> None:
        code = "'-'.join(map(lambda c: chr(c), [101, 118, 97, 108]))"
        call = _make_map_call(code)
        result = _resolve_map_join(call, "-", {})
        assert result == "e-v-a-l"

    def test_lambda_chr_tracked_name(self) -> None:
        """Lambda with tracked int-list variable (corpus pattern)."""
        code = "''.join(map(lambda c: chr(c), codes))"
        call = _make_map_call(code)
        int_list_table = {"codes": [101, 118, 97, 108]}
        result = _resolve_map_join(call, "", {}, int_list_table=int_list_table)
        assert result == "eval"

    def test_lambda_chr_tracked_name_scoped(self) -> None:
        code = "''.join(map(lambda c: chr(c), codes))"
        call = _make_map_call(code)
        int_list_table = {"func.codes": [101, 118, 97, 108]}
        result = _resolve_map_join(call, "", {}, int_list_table=int_list_table, int_list_scope="func")
        assert result == "eval"


# -- _resolve_map_join existing patterns (no regression) ---------------------


class TestResolveMapJoinExisting:
    def test_map_chr_literal_list(self) -> None:
        code = "''.join(map(chr, [101, 118, 97, 108]))"
        call = _make_map_call(code)
        assert _resolve_map_join(call, "", {}) == "eval"

    def test_map_str_literal_list(self) -> None:
        code = "''.join(map(str, ['ev', 'al']))"
        call = _make_map_call(code)
        assert _resolve_map_join(call, "", {}) == "eval"

    def test_map_chr_with_alias(self) -> None:
        code = "''.join(map(c, [101, 118, 97, 108]))"
        call = _make_map_call(code)
        assert _resolve_map_join(call, "", {"c": "chr"}) == "eval"

    def test_not_map_call(self) -> None:
        code = "''.join(filter(None, [1]))"
        tree = ast.parse(code)
        call = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "filter"
        )
        assert _resolve_map_join(call, "", {}) is None

    def test_map_unknown_func(self) -> None:
        code = "''.join(map(ord, [101]))"
        call = _make_map_call(code)
        assert _resolve_map_join(call, "", {}) is None


# -- End-to-end: corpus pattern produces EXEC-002 finding --------------------


class TestCorpusSplitMapLambda:
    def test_map_lambda_chr_produces_finding(self) -> None:
        """Corpus: map(lambda c: chr(c), codes) with tracked int-list."""
        code = (
            "codes = [101, 118, 97, 108]\n"
            "name = ''.join(map(lambda c: chr(c), codes))\n"
            "globals()[name](\"print('pwned')\")\n"
        )
        findings = _detect(code)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_map_lambda_chr_inline_list(self) -> None:
        """map(lambda c: chr(c), [ints]) inline also produces finding."""
        code = (
            "name = ''.join(map(lambda c: chr(c), [101, 118, 97, 108]))\n"
            "globals()[name](\"print('pwned')\")\n"
        )
        findings = _detect(code)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_analyze_python_map_lambda(self) -> None:
        """Full analyze_python pipeline catches map(lambda c: chr(c), ...)."""
        code = (
            "codes = [101, 118, 97, 108]\n"
            "name = ''.join(map(lambda c: chr(c), codes))\n"
            "globals()[name](\"print('pwned')\")\n"
        )
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1


# -- R-EFF001: Corpus file regression test ------------------------------------


class TestCorpusSplitMapLambdaFile:
    """Verify actual corpus file split_map_lambda.py produces EXEC-002."""

    _CORPUS = Path(__file__).resolve().parents[2] / ("corpus/red-team/2026-03-17-full/split-kwargs-evasion")

    def test_corpus_split_map_lambda(self) -> None:
        """R-EFF001: corpus split_map_lambda.py produces EXEC-002 finding."""
        code = (self._CORPUS / "split_map_lambda.py").read_text()
        findings = analyze_python(code, "split_map_lambda.py")
        rule_ids = [f.rule_id for f in findings]
        assert "EXEC-002" in rule_ids
