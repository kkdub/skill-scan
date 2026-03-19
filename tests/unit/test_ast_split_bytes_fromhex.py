"""Tests for bytes.fromhex() fragment concatenation + .decode() resolution.

Covers:
- R005: resolve_fromhex_concat resolves (bytes.fromhex('XX') + bytes.fromhex('YY')).decode()
- _resolve_fromhex: resolves single bytes.fromhex('hex_str') to bytes
- _resolve_fromhex_binop: resolves BinOp(Add) of fromhex calls
- Non-hex strings return None gracefully
- Corpus fixture pos_obfs_hex_split.py produces EXEC-002
"""

from __future__ import annotations

import ast
import pathlib

from skill_scan._ast_split_bytes import (
    _resolve_fromhex,
    _resolve_fromhex_binop,
    resolve_fromhex_concat,
)
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


def _parse_expr(code: str) -> ast.expr:
    """Parse a single expression string into an AST expr node."""
    return ast.parse(code, mode="eval").body


# -- _resolve_fromhex (single call) -------------------------------------------


class TestResolveFromhex:
    """bytes.fromhex('hex_str') resolves to bytes."""

    def test_fromhex_simple(self) -> None:
        node = _parse_expr("bytes.fromhex('6576')")
        assert isinstance(node, ast.Call)
        result = _resolve_fromhex(node)
        assert result == b"ev"

    def test_fromhex_full_eval(self) -> None:
        node = _parse_expr("bytes.fromhex('6576616c')")
        assert isinstance(node, ast.Call)
        result = _resolve_fromhex(node)
        assert result == b"eval"

    def test_fromhex_non_hex_string_returns_none(self) -> None:
        """Invalid hex string returns None without crash."""
        node = _parse_expr("bytes.fromhex('zzzz')")
        assert isinstance(node, ast.Call)
        result = _resolve_fromhex(node)
        assert result is None

    def test_fromhex_not_bytes_class_returns_none(self) -> None:
        """Non-bytes.fromhex returns None."""
        node = _parse_expr("str.fromhex('6576')")
        assert isinstance(node, ast.Call)
        result = _resolve_fromhex(node)
        assert result is None

    def test_fromhex_not_fromhex_attr_returns_none(self) -> None:
        """bytes.other() returns None."""
        node = _parse_expr("bytes.decode('6576')")
        assert isinstance(node, ast.Call)
        result = _resolve_fromhex(node)
        assert result is None

    def test_fromhex_no_args_returns_none(self) -> None:
        """bytes.fromhex() with no args returns None."""
        node = _parse_expr("bytes.fromhex()")
        assert isinstance(node, ast.Call)
        result = _resolve_fromhex(node)
        assert result is None

    def test_fromhex_variable_arg_returns_none(self) -> None:
        """bytes.fromhex(var) with non-literal arg returns None."""
        node = _parse_expr("bytes.fromhex(x)")
        assert isinstance(node, ast.Call)
        result = _resolve_fromhex(node)
        assert result is None


# -- _resolve_fromhex_binop (concatenation) -----------------------------------


class TestResolveFromhexBinop:
    """BinOp(Add) of fromhex calls resolves to concatenated bytes."""

    def test_binop_two_fromhex_eval(self) -> None:
        node = _parse_expr("bytes.fromhex('6576') + bytes.fromhex('616c')")
        assert isinstance(node, ast.BinOp)
        result = _resolve_fromhex_binop(node)
        assert result == b"eval"

    def test_binop_three_fromhex(self) -> None:
        node = _parse_expr("bytes.fromhex('65') + bytes.fromhex('76') + bytes.fromhex('616c')")
        assert isinstance(node, ast.BinOp)
        result = _resolve_fromhex_binop(node)
        assert result == b"eval"

    def test_binop_non_add_returns_none(self) -> None:
        """Non-Add BinOp returns None."""
        node = _parse_expr("bytes.fromhex('6576') - bytes.fromhex('616c')")
        assert isinstance(node, ast.BinOp)
        result = _resolve_fromhex_binop(node)
        assert result is None

    def test_binop_mixed_non_fromhex_returns_none(self) -> None:
        """BinOp with non-fromhex operand returns None."""
        node = _parse_expr("bytes.fromhex('6576') + b'al'")
        assert isinstance(node, ast.BinOp)
        result = _resolve_fromhex_binop(node)
        assert result is None

    def test_single_fromhex_call_not_binop(self) -> None:
        """Single fromhex call is not a BinOp."""
        node = _parse_expr("bytes.fromhex('6576616c')")
        assert isinstance(node, ast.Call)
        result = _resolve_fromhex_binop(node)
        assert result is None


# -- resolve_fromhex_concat (full: decode wrapper) ----------------------------


class TestResolveFromhexConcat:
    """(bytes.fromhex('XX') + bytes.fromhex('YY')).decode() resolves to string."""

    def test_fromhex_concat_decode_eval(self) -> None:
        node = _parse_expr("(bytes.fromhex('6576') + bytes.fromhex('616c')).decode()")
        assert isinstance(node, ast.Call)
        result = resolve_fromhex_concat(node)
        assert result == "eval"

    def test_fromhex_concat_decode_system(self) -> None:
        node = _parse_expr("(bytes.fromhex('7379') + bytes.fromhex('7374656d')).decode()")
        assert isinstance(node, ast.Call)
        result = resolve_fromhex_concat(node)
        assert result == "system"

    def test_fromhex_concat_decode_with_encoding(self) -> None:
        node = _parse_expr("(bytes.fromhex('6576') + bytes.fromhex('616c')).decode('utf-8')")
        assert isinstance(node, ast.Call)
        result = resolve_fromhex_concat(node)
        assert result == "eval"

    def test_fromhex_single_decode(self) -> None:
        """Single fromhex (no concat) with .decode() also resolves."""
        node = _parse_expr("bytes.fromhex('6576616c').decode()")
        assert isinstance(node, ast.Call)
        result = resolve_fromhex_concat(node)
        assert result == "eval"

    def test_fromhex_no_decode_returns_none(self) -> None:
        """fromhex concat without .decode() returns None."""
        node = _parse_expr("bytes.fromhex('6576') + bytes.fromhex('616c')")
        assert isinstance(node, ast.BinOp)
        result = resolve_fromhex_concat(node)
        assert result is None

    def test_fromhex_invalid_hex_returns_none(self) -> None:
        """Invalid hex in fromhex returns None."""
        node = _parse_expr("(bytes.fromhex('zzzz') + bytes.fromhex('616c')).decode()")
        assert isinstance(node, ast.Call)
        result = resolve_fromhex_concat(node)
        assert result is None

    def test_non_fromhex_decode_returns_none(self) -> None:
        """Non-fromhex .decode() call returns None."""
        node = _parse_expr("bytearray(b'eval').decode()")
        assert isinstance(node, ast.Call)
        result = resolve_fromhex_concat(node)
        assert result is None


# -- Full-path detection (split detector) ------------------------------------


class TestFromhexConcatDetection:
    """R005: fromhex concat triggers EXEC-002 via split detector."""

    def test_fromhex_concat_triggers_exec002(self) -> None:
        code = "name = (bytes.fromhex('6576') + bytes.fromhex('616c')).decode()"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_fromhex_single_triggers_exec002(self) -> None:
        code = "name = bytes.fromhex('6576616c').decode()"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_fromhex_safe_no_finding(self) -> None:
        """Non-dangerous fromhex content produces no finding."""
        code = "name = (bytes.fromhex('68656c6c6f')).decode()"
        assert len(_detect(code)) == 0

    def test_fromhex_import_triggers_exec006(self) -> None:
        """fromhex building __import__ should produce EXEC-006."""
        # __import__ = 5f5f696d706f72745f5f
        code = "name = bytes.fromhex('5f5f696d706f72745f5f').decode()"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"


# -- Full pipeline (analyze_python) acceptance ---------------------------------


class TestFromhexAcceptance:
    """R005 acceptance: analyze_python detects fromhex patterns."""

    def test_fromhex_concat_full_pipeline(self) -> None:
        code = "name = (bytes.fromhex('6576') + bytes.fromhex('616c')).decode()"
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_fromhex_safe_no_false_positive(self) -> None:
        code = "x = bytes.fromhex('68656c6c6f').decode()"
        findings = analyze_python(code, _FILE)
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0


# -- Corpus fixture test ------------------------------------------------------


class TestFromhexCorpus:
    """Corpus fixture produces expected findings."""

    def test_pos_obfs_hex_split_fixture(self) -> None:
        fixture = (
            pathlib.Path(__file__).resolve().parent.parent
            / "fixtures"
            / "split_evasion"
            / "pos_obfs_hex_split.py"
        )
        code = fixture.read_text()
        findings = analyze_python(code, str(fixture))
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
