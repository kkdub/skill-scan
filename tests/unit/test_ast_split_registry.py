"""Tests for the _RESOLVERS registry pattern in _ast_split_detector.

Covers the registry tuple definition, predicate functions, resolver
dispatch via the for-loop, and the common resolver function signatures.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from skill_scan._ast_split_detector import (
    _RESOLVERS,
    _is_binop_add,
    _is_binop_mod,
    _is_call,
    _is_fstr,
    _is_replace,
    detect_split_evasion,
)
from skill_scan._ast_split_resolve import (
    _resolve_replace_chain,
    resolve_binop_chain,
    resolve_call,
    resolve_fstring,
    resolve_percent_format,
)
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


# -- Registry structure tests --


class TestRegistryStructure:
    """Verify _RESOLVERS tuple is correctly defined."""

    def test_resolvers_is_tuple(self) -> None:
        assert isinstance(_RESOLVERS, tuple)

    def test_resolvers_has_required_entries(self) -> None:
        """Registry contains all required resolver entries (extensible)."""
        preds = [p for p, _ in _RESOLVERS]
        # All required predicates must be present
        for required in (_is_binop_add, _is_binop_mod, _is_fstr, _is_replace, _is_call):
            assert required in preds, f"Missing required predicate: {required.__name__}"

    def test_each_entry_is_predicate_resolver_pair(self) -> None:
        for pred, resolver in _RESOLVERS:
            assert callable(pred), f"{pred} is not callable"
            assert callable(resolver), f"{resolver} is not callable"

    def test_replace_before_call_in_registry(self) -> None:
        """Replace must be dispatched before generic Call (more specific first)."""
        preds = [p for p, _ in _RESOLVERS]
        assert preds.index(_is_replace) < preds.index(_is_call)

    def test_required_resolver_functions_present(self) -> None:
        """All required resolver functions are registered."""
        resolvers = [r for _, r in _RESOLVERS]
        for required in (
            resolve_binop_chain,
            resolve_percent_format,
            resolve_fstring,
            _resolve_replace_chain,
            resolve_call,
        ):
            assert required in resolvers, f"Missing resolver: {required.__name__}"


# -- Predicate tests --


class TestPredicates:
    """Verify predicate functions match the correct AST node types."""

    def test_is_binop_add_true(self) -> None:
        node = _PARSE("a + b").body[0].value  # type: ignore[attr-defined]
        assert _is_binop_add(node) is True

    def test_is_binop_add_false_on_mod(self) -> None:
        node = _PARSE("a % b").body[0].value  # type: ignore[attr-defined]
        assert _is_binop_add(node) is False

    def test_is_binop_mod_true(self) -> None:
        node = _PARSE("a % b").body[0].value  # type: ignore[attr-defined]
        assert _is_binop_mod(node) is True

    def test_is_binop_mod_false_on_add(self) -> None:
        node = _PARSE("a + b").body[0].value  # type: ignore[attr-defined]
        assert _is_binop_mod(node) is False

    def test_is_fstr_true(self) -> None:
        node = _PARSE("f'{x}'").body[0].value  # type: ignore[attr-defined]
        assert _is_fstr(node) is True

    def test_is_fstr_false_on_str(self) -> None:
        node = _PARSE("'hello'").body[0].value  # type: ignore[attr-defined]
        assert _is_fstr(node) is False

    def test_is_replace_true(self) -> None:
        node = _PARSE("'x'.replace('a', 'b')").body[0].value  # type: ignore[attr-defined]
        assert _is_replace(node) is True

    def test_is_replace_false_on_plain_call(self) -> None:
        node = _PARSE("foo()").body[0].value  # type: ignore[attr-defined]
        assert _is_replace(node) is False

    def test_is_call_true(self) -> None:
        node = _PARSE("foo()").body[0].value  # type: ignore[attr-defined]
        assert _is_call(node) is True

    def test_is_call_false_on_name(self) -> None:
        node = _PARSE("x").body[0].value  # type: ignore[attr-defined]
        assert _is_call(node) is False


# -- Common resolver signature tests --


class TestResolverSignatures:
    """Verify all resolvers share the common signature."""

    @pytest.mark.parametrize(
        "func",
        [resolve_binop_chain, resolve_percent_format, resolve_fstring, _resolve_replace_chain, resolve_call],
        ids=["binop_chain", "percent_format", "fstring", "replace_chain", "call"],
    )
    def test_resolver_accepts_node_st_scope_alias_map(self, func: object) -> None:
        sig = inspect.signature(func)  # type: ignore[arg-type]
        params = list(sig.parameters.keys())
        # Must have node, symbol_table, scope as positional
        assert "node" in params
        assert "symbol_table" in params
        assert "scope" in params
        # Must have alias_map as keyword argument
        assert "alias_map" in params

    @pytest.mark.parametrize(
        "func",
        [resolve_binop_chain, resolve_percent_format, resolve_fstring, _resolve_replace_chain, resolve_call],
        ids=["binop_chain", "percent_format", "fstring", "replace_chain", "call"],
    )
    def test_resolver_alias_map_defaults_to_none(self, func: object) -> None:
        sig = inspect.signature(func)  # type: ignore[arg-type]
        alias_map_param = sig.parameters["alias_map"]
        assert alias_map_param.default is None

    @pytest.mark.parametrize(
        "func",
        [resolve_binop_chain, resolve_percent_format, resolve_fstring, _resolve_replace_chain, resolve_call],
        ids=["binop_chain", "percent_format", "fstring", "replace_chain", "call"],
    )
    def test_resolver_returns_str_or_none(self, func: object) -> None:
        import types

        hints = func.__annotations__
        ret = hints.get("return")
        assert ret in ("str | None", str | None, types.UnionType), (
            f"Expected str | None return annotation, got {ret!r}"
        )


# -- Dispatch via registry tests --


class TestRegistryDispatch:
    """Verify _try_resolve_split dispatches through the registry correctly."""

    def test_binop_add_dispatches_through_registry(self) -> None:
        """BinOp(Add) concatenation still works via registry dispatch."""
        findings = _detect("a = 'ev'\nb = 'al'\nc = a + b")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"
        assert "eval" in findings[0].description

    def test_binop_mod_dispatches_through_registry(self) -> None:
        """BinOp(Mod) percent-format still works via registry dispatch."""
        findings = _detect("a = 'ev'\nb = 'al'\nresult = '%s%s' % (a, b)")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_joined_str_dispatches_through_registry(self) -> None:
        """JoinedStr f-string still works via registry dispatch."""
        findings = _detect("a = 'ev'\nb = 'al'\nc = f'{a}{b}'")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_call_join_dispatches_through_registry(self) -> None:
        """Call ''.join() still works via registry dispatch."""
        findings = _detect("a = 'ev'\nb = 'al'\nc = ''.join([a, b])")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_call_format_dispatches_through_registry(self) -> None:
        """Call '{}{}'.format() still works via registry dispatch."""
        findings = _detect("a = 'ev'\nb = 'al'\nresult = '{}{}'.format(a, b)")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_call_bytes_dispatches_through_registry(self) -> None:
        """Bytes-constructor decode still works via registry dispatch."""
        findings = _detect("result = bytearray(b'eval').decode('utf-8')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_call_return_dispatches_through_registry(self) -> None:
        """Call-return resolution still works via registry dispatch."""
        code = "def a(): return 'ev'\ndef b(): return 'al'\nresult = a() + b()"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_safe_patterns_still_produce_no_findings(self) -> None:
        """Registry dispatch does not change safe-pattern behavior."""
        assert len(_detect("a = 'hello'\nb = 'world'\nc = a + b")) == 0

    def test_unresolvable_still_returns_none(self) -> None:
        """Unresolvable nodes produce no findings through registry."""
        assert len(_detect("a = 'ev'\nc = a + unknown")) == 0


# -- resolve_percent_format wrapper tests --


class TestResolvePercentFormat:
    """Verify the resolve_percent_format registry wrapper."""

    def test_resolves_percent_format_to_string(self) -> None:
        tree = _PARSE("result = '%s%s' % ('ev', 'al')")
        node = tree.body[0].value  # type: ignore[attr-defined]
        result = resolve_percent_format(node, {}, "")
        assert result == "eval"

    def test_returns_none_for_non_percent_format(self) -> None:
        tree = _PARSE("result = 1 % 2")
        node = tree.body[0].value  # type: ignore[attr-defined]
        result = resolve_percent_format(node, {}, "")
        assert result is None


# -- resolve_call wrapper tests --


class TestResolveCall:
    """Verify the resolve_call registry wrapper."""

    def test_resolves_join_call(self) -> None:
        tree = _PARSE("result = ''.join(['ev', 'al'])")
        node = tree.body[0].value  # type: ignore[attr-defined]
        result = resolve_call(node, {}, "")
        assert result == "eval"

    def test_resolves_format_call(self) -> None:
        tree = _PARSE("result = '{}{}'.format('ev', 'al')")
        node = tree.body[0].value  # type: ignore[attr-defined]
        result = resolve_call(node, {}, "")
        assert result == "eval"

    def test_resolves_bytes_constructor(self) -> None:
        tree = _PARSE("result = bytearray(b'eval').decode('utf-8')")
        node = tree.body[0].value  # type: ignore[attr-defined]
        result = resolve_call(node, {}, "")
        assert result == "eval"

    def test_resolves_call_return(self) -> None:
        st = {"func()": "eval"}
        tree = _PARSE("result = func()")
        node = tree.body[0].value  # type: ignore[attr-defined]
        result = resolve_call(node, st, "")
        assert result == "eval"

    def test_returns_none_for_unknown_call(self) -> None:
        tree = _PARSE("result = unknown()")
        node = tree.body[0].value  # type: ignore[attr-defined]
        result = resolve_call(node, {}, "")
        assert result is None
