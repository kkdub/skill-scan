"""Tests for internal helpers in _ast_kwargs_detector.

Unit tests for _extract_dict_literal, _lookup_symbol_table_dict,
_kwarg_matches, and _resolve_kwargs_dict.
"""

from __future__ import annotations

import ast

from skill_scan._ast_kwargs_detector import (
    _extract_dict_literal,
    _kwarg_matches,
    _lookup_symbol_table_dict,
    _resolve_kwargs_dict,
)

_PARSE = ast.parse


class TestExtractDictLiteral:
    """_extract_dict_literal extracts constant key-value pairs."""

    def test_simple_dict(self) -> None:
        node = _PARSE("{'a': 1, 'b': 'hello'}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result == {"a": "1", "b": "hello"}

    def test_non_constant_values_skipped(self) -> None:
        node = _PARSE("{'a': x, 'b': 1}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result == {"b": "1"}

    def test_non_string_keys_skipped(self) -> None:
        node = _PARSE("{1: 'a', 'b': 'c'}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result == {"b": "c"}

    def test_spread_returns_none(self) -> None:
        node = _PARSE("{**base, 'shell': True}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is None

    def test_spread_after_constant_returns_none(self) -> None:
        node = _PARSE("{'shell': True, **base}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is None


class TestLookupSymbolTableDict:
    """_lookup_symbol_table_dict reconstructs dict from composite keys."""

    def test_reconstructs_dict(self) -> None:
        st = {"opts[shell]": "True", "opts[stdout]": "-1", "other": "val"}
        result = _lookup_symbol_table_dict("opts", st)
        assert result == {"shell": "True", "stdout": "-1"}

    def test_empty_when_no_matches(self) -> None:
        st = {"other[key]": "val"}
        result = _lookup_symbol_table_dict("opts", st)
        assert result == {}

    def test_partial_name_no_collision(self) -> None:
        st = {"opts[shell]": "True", "myopts[shell]": "False"}
        result = _lookup_symbol_table_dict("opts", st)
        assert result == {"shell": "True"}


class TestKwargMatches:
    """_kwarg_matches compares values as strings."""

    def test_true_matches_string_true(self) -> None:
        assert _kwarg_matches({"shell": "True"}, "shell", True) is True

    def test_false_does_not_match_true(self) -> None:
        assert _kwarg_matches({"shell": "False"}, "shell", True) is False

    def test_missing_key_no_match(self) -> None:
        assert _kwarg_matches({"other": "True"}, "shell", True) is False


class TestResolveKwargsDict:
    """_resolve_kwargs_dict dispatches to correct resolver."""

    def test_dict_node_resolved(self) -> None:
        node = _PARSE("{'shell': True}").body[0].value  # type: ignore[attr-defined]
        result = _resolve_kwargs_dict(node, {}, {})
        assert result == {"shell": "True"}

    def test_name_node_resolved_via_symbol_table(self) -> None:
        node = _PARSE("opts").body[0].value  # type: ignore[attr-defined]
        st = {"opts[shell]": "True"}
        result = _resolve_kwargs_dict(node, st, {})
        assert result == {"shell": "True"}

    def test_name_node_resolved_via_dict_assigns(self) -> None:
        node = _PARSE("opts").body[0].value  # type: ignore[attr-defined]
        da = {"opts": {"shell": "True"}}
        result = _resolve_kwargs_dict(node, {}, da)
        assert result == {"shell": "True"}

    def test_non_resolvable_returns_none(self) -> None:
        node = _PARSE("f()").body[0].value  # type: ignore[attr-defined]
        result = _resolve_kwargs_dict(node, {}, {})
        assert result is None
