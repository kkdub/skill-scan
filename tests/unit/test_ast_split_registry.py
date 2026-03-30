"""Tests for the _RESOLVERS registry pattern in _ast_split_detector.

Covers registry definition, predicates, dispatch, return types, and labels.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from skill_scan._ast_split_bytes import resolve_fromhex_concat
from skill_scan._ast_split_detector import (
    _RESOLVERS,
    _Resolver,
    _is_binop_add,
    _is_binop_mod,
    _is_call,
    _is_fstr,
    _is_replace,
    _try_resolve_split,
    detect_split_evasion,
)
from skill_scan._ast_split_resolve import (
    _resolve_case_method_chain,
    _resolve_replace_chain,
    resolve_binop_chain,
    resolve_call,
    resolve_call_return,
    resolve_expr,
    resolve_fstring,
    resolve_operand,
    resolve_percent_format,
    resolve_subscript,
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
            _resolve_case_method_chain,
            resolve_subscript,
            resolve_call,
        ):
            assert required in resolvers, f"Missing resolver: {required.__name__}"


# -- Type alias test (Criterion 1) --


class TestResolverTypeAlias:
    """Verify _Resolver type alias expects tuple return."""

    def test_resolver_alias_is_tuple_based(self) -> None:
        """_Resolver callable return type must be tuple[str, str] | None."""
        from typing import get_args

        args = get_args(_Resolver)
        assert len(args) == 2, f"Expected 2 type args, got {args}"
        assert args[1] == tuple[str, str] | None, f"Got {args[1]!r}"


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


# -- Resolver signature tests (Criterion 3) --

_RESOLVER_PARAMS: list[tuple[object, str]] = [
    (resolve_binop_chain, "binop_chain"),
    (resolve_percent_format, "percent_format"),
    (resolve_fstring, "fstring"),
    (_resolve_replace_chain, "replace_chain"),
    (_resolve_case_method_chain, "case_method_chain"),
    (resolve_subscript, "subscript"),
    (resolve_call, "call"),
]
_ALL_RESOLVERS = [f for f, _ in _RESOLVER_PARAMS]
_RESOLVER_IDS = [i for _, i in _RESOLVER_PARAMS]


class TestResolverSignatures:
    """Verify all seven resolvers share the common signature and return type."""

    @pytest.mark.parametrize("func", _ALL_RESOLVERS, ids=_RESOLVER_IDS)
    def test_resolver_accepts_node_st_scope_alias_map(self, func: object) -> None:
        sig = inspect.signature(func)  # type: ignore[arg-type]
        params = list(sig.parameters.keys())
        assert "node" in params
        assert "symbol_table" in params
        assert "scope" in params
        assert "alias_map" in params

    @pytest.mark.parametrize("func", _ALL_RESOLVERS, ids=_RESOLVER_IDS)
    def test_resolver_alias_map_defaults_to_none(self, func: object) -> None:
        sig = inspect.signature(func)  # type: ignore[arg-type]
        assert sig.parameters["alias_map"].default is None

    @pytest.mark.parametrize("func", _ALL_RESOLVERS, ids=_RESOLVER_IDS)
    def test_resolver_returns_tuple_or_none(self, func: object) -> None:
        """All seven registry resolvers must return tuple[str, str] | None."""
        ret = func.__annotations__.get("return")
        assert ret in ("tuple[str, str] | None", tuple[str, str] | None), (
            f"Expected tuple[str, str] | None, got {ret!r}"
        )


# -- Internal helper return types (Criterion 4) --


class TestInternalHelpersReturnStr:
    """Internal helpers must keep str | None return type (not changed to tuple)."""

    @pytest.mark.parametrize(
        "func",
        [resolve_expr, resolve_operand, resolve_call_return, resolve_fromhex_concat],
        ids=["resolve_expr", "resolve_operand", "resolve_call_return", "resolve_fromhex_concat"],
    )
    def test_helper_returns_str_or_none(self, func: object) -> None:
        ret = func.__annotations__.get("return")
        assert ret in ("str | None", str | None), f"Expected str | None return annotation, got {ret!r}"


# -- _try_resolve_split unpacking (Criterion 2) --


class TestTryResolveSplitUnpacking:
    """_try_resolve_split must unpack resolver tuples directly."""

    def test_no_resolve_call_return_reference(self) -> None:
        """Source must not reference resolve_call_return (old equality-check hack)."""
        source = inspect.getsource(_try_resolve_split)
        assert "resolve_call_return" not in source, (
            "_try_resolve_split should unpack label from resolver tuple"
        )


# -- Dispatch via registry tests --


class TestRegistryDispatch:
    """Verify _try_resolve_split dispatches through the registry correctly."""

    def test_binop_mod_dispatches_through_registry(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nresult = '%s%s' % (a, b)")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_joined_str_dispatches_through_registry(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = f'{a}{b}'")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_call_join_dispatches_through_registry(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nc = ''.join([a, b])")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_call_format_dispatches_through_registry(self) -> None:
        findings = _detect("a = 'ev'\nb = 'al'\nresult = '{}{}'.format(a, b)")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_call_bytes_dispatches_through_registry(self) -> None:
        findings = _detect("result = bytearray(b'eval').decode('utf-8')")
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_call_return_dispatches_through_registry(self) -> None:
        code = "def a(): return 'ev'\ndef b(): return 'al'\nresult = a() + b()"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_unresolvable_still_returns_none(self) -> None:
        assert len(_detect("a = 'ev'\nc = a + unknown")) == 0


# -- Resolver return value tests (Criteria 5 & 6) --


class TestResolverReturnValues:
    """Direct resolver calls must return (value, label) tuples or None."""

    # Criterion 6: always 'split variable'

    def test_percent_format_split_variable(self) -> None:
        node = _PARSE("'%s%s' % ('ev', 'al')").body[0].value  # type: ignore[attr-defined]
        assert resolve_percent_format(node, {}, "") == ("eval", "split variable")

    def test_percent_format_none(self) -> None:
        node = _PARSE("1 % 2").body[0].value  # type: ignore[attr-defined]
        assert resolve_percent_format(node, {}, "") is None

    def test_subscript_split_variable(self) -> None:
        node = _PARSE("d['key']").body[0].value  # type: ignore[attr-defined]
        assert resolve_subscript(node, {"d[key]": "eval"}, "") == ("eval", "split variable")

    def test_case_method_chain_split_variable(self) -> None:
        tree = _PARSE("x = 'EVAL'\ny = x.lower()")
        st = build_symbol_table(tree)
        node = tree.body[1].value  # type: ignore[attr-defined]
        assert _resolve_case_method_chain(node, st, "") == ("eval", "split variable")

    # Criterion 5: 'call-return' when leaf resolved via resolve_call_return

    def test_call_join_split_variable(self) -> None:
        node = _PARSE("''.join(['ev', 'al'])").body[0].value  # type: ignore[attr-defined]
        assert resolve_call(node, {}, "") == ("eval", "split variable")

    def test_call_format_split_variable(self) -> None:
        node = _PARSE("'{}{}'.format('ev', 'al')").body[0].value  # type: ignore[attr-defined]
        assert resolve_call(node, {}, "") == ("eval", "split variable")

    def test_call_bytes_split_variable(self) -> None:
        node = _PARSE("bytearray(b'eval').decode('utf-8')").body[0].value  # type: ignore[attr-defined]
        assert resolve_call(node, {}, "") == ("eval", "split variable")

    def test_call_return_label(self) -> None:
        node = _PARSE("func()").body[0].value  # type: ignore[attr-defined]
        assert resolve_call(node, {"func()": "eval"}, "") == ("eval", "call-return")

    def test_call_unknown_none(self) -> None:
        node = _PARSE("unknown()").body[0].value  # type: ignore[attr-defined]
        assert resolve_call(node, {}, "") is None

    def test_binop_chain_split_variable(self) -> None:
        node = _PARSE("'ev' + 'al'").body[0].value  # type: ignore[attr-defined]
        assert resolve_binop_chain(node, {}, "") == ("eval", "split variable")

    def test_binop_chain_call_return_label(self) -> None:
        """Concat of call-returns gets 'call-return' label."""
        node = _PARSE("a() + b()").body[0].value  # type: ignore[attr-defined]
        assert resolve_binop_chain(node, {"a()": "ev", "b()": "al"}, "") == ("eval", "call-return")

    def test_fstring_split_variable(self) -> None:
        tree = _PARSE("a = 'ev'\nb = 'al'\nc = f'{a}{b}'")
        st = build_symbol_table(tree)
        node = tree.body[2].value  # type: ignore[attr-defined]
        assert resolve_fstring(node, st, "") == ("eval", "split variable")

    def test_fstring_call_return_label(self) -> None:
        """f-string with call-return values gets 'call-return' label."""
        node = _PARSE("f'{a()}{b()}'").body[0].value  # type: ignore[attr-defined]
        assert resolve_fstring(node, {"a()": "ev", "b()": "al"}, "") == ("eval", "call-return")


# -- Operand unpacking (Criterion 7) --


class TestOperandUnpacking:
    """resolve_operand must unpack tuple returns from registry functions to str."""

    def test_resolve_operand_nested_binop_returns_str(self) -> None:
        """resolve_operand on nested BinOp must return str, not tuple."""
        outer = _PARSE("('ev' + 'al') + 'x'").body[0].value  # type: ignore[attr-defined]
        assert isinstance(outer, ast.BinOp)
        left_result = resolve_operand(outer.left, {}, "")
        assert left_result == "eval"
        assert isinstance(left_result, str)
