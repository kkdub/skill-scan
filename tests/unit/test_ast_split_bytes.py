"""Tests for bytes/bytearray/str/codecs constructor detection.

Covers:
- resolve_bytes_constructor(): bytearray(b'...').decode(), str(b'...',enc), codecs.decode(b'...',enc)
- R005: all three bytes-constructor patterns detected via full pipeline
- R-IMP004: non-literal bytes arguments return None without error
- R-EFF004: each variant exercised independently
"""

from __future__ import annotations

import ast
import textwrap


from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_bytes import (
    _resolve_bytearray_decode,
    _resolve_codecs_decode,
    _resolve_str_bytes,
    resolve_bytes_constructor,
)
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


def _parse_call(code: str) -> ast.Call:
    """Parse a single call expression string into an AST Call node."""
    node = ast.parse(code, mode="eval").body
    assert isinstance(node, ast.Call)
    return node


# -- bytearray(b'...').decode() ------------------------------------------------


class TestBytearrayDecode:
    """R005: bytearray(b'...').decode() resolves to a string."""

    def test_bytearray_decode_eval(self) -> None:
        node = _parse_call("bytearray(b'eval').decode()")
        result = _resolve_bytearray_decode(node)
        assert result == "eval"

    def test_bytearray_decode_system(self) -> None:
        node = _parse_call("bytearray(b'system').decode()")
        result = _resolve_bytearray_decode(node)
        assert result == "system"

    def test_bytearray_non_bytes_arg_returns_none(self) -> None:
        """R-IMP004: non-literal bytes argument returns None."""
        node = _parse_call("bytearray(x).decode()")
        assert _resolve_bytearray_decode(node) is None

    def test_bytearray_string_arg_returns_none(self) -> None:
        """R-IMP004: string argument instead of bytes returns None."""
        node = _parse_call("bytearray('eval').decode()")
        assert _resolve_bytearray_decode(node) is None

    def test_bytearray_no_decode_returns_none(self) -> None:
        """bytearray(b'eval') without .decode() is not matched."""
        node = _parse_call("bytearray(b'eval')")
        assert _resolve_bytearray_decode(node) is None

    def test_bytearray_with_keywords_returns_none(self) -> None:
        """bytearray with keyword arguments returns None."""
        node = _parse_call("bytearray(source=b'eval').decode()")
        assert _resolve_bytearray_decode(node) is None


# -- str(b'...', encoding) ----------------------------------------------------


class TestStrBytesConstructor:
    """R005: str(b'...', 'utf-8') resolves to a string."""

    def test_str_bytes_exec(self) -> None:
        node = _parse_call("str(b'exec', 'utf-8')")
        result = _resolve_str_bytes(node)
        assert result == "exec"

    def test_str_bytes_popen(self) -> None:
        node = _parse_call("str(b'popen', 'ascii')")
        result = _resolve_str_bytes(node)
        assert result == "popen"

    def test_str_non_bytes_first_arg_returns_none(self) -> None:
        """R-IMP004: non-bytes first argument returns None."""
        node = _parse_call("str(42, 'utf-8')")
        assert _resolve_str_bytes(node) is None

    def test_str_variable_first_arg_returns_none(self) -> None:
        """R-IMP004: variable first argument returns None."""
        node = _parse_call("str(x, 'utf-8')")
        assert _resolve_str_bytes(node) is None

    def test_str_non_string_encoding_returns_none(self) -> None:
        """Non-string encoding argument returns None."""
        node = _parse_call("str(b'exec', 42)")
        assert _resolve_str_bytes(node) is None

    def test_str_single_arg_returns_none(self) -> None:
        """str() with only one argument is not matched (normal str() call)."""
        node = _parse_call("str(b'exec')")
        assert _resolve_str_bytes(node) is None

    def test_str_with_keywords_returns_none(self) -> None:
        """str() with keyword arguments returns None."""
        node = _parse_call("str(b'exec', encoding='utf-8')")
        assert _resolve_str_bytes(node) is None

    def test_str_not_str_func_returns_none(self) -> None:
        """Non-str() function name returns None."""
        node = _parse_call("repr(b'exec', 'utf-8')")
        assert _resolve_str_bytes(node) is None


# -- codecs.decode(b'...', encoding) ------------------------------------------


class TestCodecsDecode:
    """R005: codecs.decode(b'...', 'utf-8') resolves to a string."""

    def test_codecs_decode_system(self) -> None:
        node = _parse_call("codecs.decode(b'system', 'utf-8')")
        result = _resolve_codecs_decode(node, {})
        assert result == "system"

    def test_codecs_decode_with_alias(self) -> None:
        """codecs aliased as 'c' is recognized via alias_map."""
        node = _parse_call("c.decode(b'eval', 'utf-8')")
        result = _resolve_codecs_decode(node, {"c": "codecs"})
        assert result == "eval"

    def test_codecs_decode_non_bytes_returns_none(self) -> None:
        """R-IMP004: non-bytes first argument returns None."""
        node = _parse_call("codecs.decode(x, 'utf-8')")
        assert _resolve_codecs_decode(node, {}) is None

    def test_codecs_decode_non_codecs_module_returns_none(self) -> None:
        """Non-codecs module returns None."""
        node = _parse_call("json.decode(b'system', 'utf-8')")
        assert _resolve_codecs_decode(node, {}) is None

    def test_codecs_decode_single_arg_returns_none(self) -> None:
        """codecs.decode with single arg returns None."""
        node = _parse_call("codecs.decode(b'system')")
        assert _resolve_codecs_decode(node, {}) is None

    def test_codecs_decode_with_keywords_returns_none(self) -> None:
        """codecs.decode with keyword arguments returns None."""
        node = _parse_call("codecs.decode(b'system', encoding='utf-8')")
        assert _resolve_codecs_decode(node, {}) is None


# -- resolve_bytes_constructor (unified dispatcher) ----------------------------


class TestResolveBytesConstructor:
    """Unified dispatcher resolves all three patterns."""

    def test_dispatches_bytearray(self) -> None:
        node = _parse_call("bytearray(b'eval').decode()")
        assert resolve_bytes_constructor(node) == "eval"

    def test_dispatches_str_bytes(self) -> None:
        node = _parse_call("str(b'exec', 'utf-8')")
        assert resolve_bytes_constructor(node) == "exec"

    def test_dispatches_codecs_decode(self) -> None:
        node = _parse_call("codecs.decode(b'system', 'utf-8')")
        assert resolve_bytes_constructor(node) == "system"

    def test_codecs_with_alias_map(self) -> None:
        node = _parse_call("c.decode(b'popen', 'utf-8')")
        assert resolve_bytes_constructor(node, alias_map={"c": "codecs"}) == "popen"

    def test_unrecognized_call_returns_none(self) -> None:
        node = _parse_call("len([1, 2, 3])")
        assert resolve_bytes_constructor(node) is None


# -- Full path detection (split detector) --------------------------------------


class TestBytesConstructorDetection:
    """R005: bytes-constructor patterns trigger EXEC-002 via split detector."""

    def test_bytearray_decode_triggers_exec002(self) -> None:
        findings = _detect("_result = bytearray(b'eval').decode()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_str_bytes_triggers_exec002(self) -> None:
        findings = _detect("_result = str(b'exec', 'utf-8')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_codecs_decode_triggers_exec002(self) -> None:
        code = textwrap.dedent("""\
            import codecs
            _result = codecs.decode(b'system', 'utf-8')
        """)
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_safe_bytes_constructor_no_finding(self) -> None:
        """Non-dangerous content produces no finding."""
        assert len(_detect("_result = bytearray(b'hello').decode()")) == 0
        assert len(_detect("_result = str(b'world', 'utf-8')")) == 0

    def test_dynamic_import_via_bytes_triggers_exec006(self) -> None:
        """bytes constructor building __import__ should produce EXEC-006."""
        findings = _detect("_result = bytearray(b'__import__').decode()")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"


# -- Full pipeline (analyze_python) acceptance ---------------------------------


class TestBytesConstructorAcceptance:
    """R005 acceptance: analyze_python detects all three bytes-constructor patterns."""

    def test_bytearray_decode_full_pipeline(self) -> None:
        code = "_result = bytearray(b'eval').decode()"
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("eval" in f.description for f in exec_findings)

    def test_str_bytes_full_pipeline(self) -> None:
        code = "_result = str(b'exec', 'utf-8')"
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("exec" in f.description for f in exec_findings)

    def test_codecs_decode_full_pipeline(self) -> None:
        code = textwrap.dedent("""\
            import codecs
            _result = codecs.decode(b'system', 'utf-8')
        """)
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("system" in f.description for f in exec_findings)

    def test_codecs_aliased_full_pipeline(self) -> None:
        code = textwrap.dedent("""\
            import codecs as c
            _result = c.decode(b'eval', 'utf-8')
        """)
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_safe_bytes_no_false_positive(self) -> None:
        """Safe bytes constructors produce no dangerous findings."""
        code = textwrap.dedent("""\
            import codecs
            safe1 = bytearray(b'hello').decode()
            safe2 = str(b'world', 'utf-8')
            safe3 = codecs.decode(b'greeting', 'utf-8')
        """)
        findings = analyze_python(code, _FILE)
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0
