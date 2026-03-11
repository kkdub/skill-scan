"""Tests for AST symbol table builder.

Covers build_symbol_table() with module-level assignments, function scoping,
variable indirection chains, circular references, and edge cases.
"""

from __future__ import annotations

import ast


from skill_scan._ast_symbol_table import (
    MAX_RESOLVE_DEPTH,
    _Ref,
    _collect_assignments,
    _follow_chain,
    _resolve_indirections,
    build_symbol_table,
)


_PARSE = ast.parse


# -- R001: Simple string assignments ----------------------------------------


class TestSimpleAssignments:
    def test_string_constant_tracked(self) -> None:
        result = build_symbol_table(_PARSE("x = 'hello'"))
        assert result == {"x": "hello"}

    def test_multiple_string_assignments(self) -> None:
        code = "a = 'foo'\nb = 'bar'"
        result = build_symbol_table(_PARSE(code))
        assert result == {"a": "foo", "b": "bar"}

    def test_int_assignment_skipped(self) -> None:
        result = build_symbol_table(_PARSE("x = 42"))
        assert result == {}

    def test_list_assignment_skipped(self) -> None:
        result = build_symbol_table(_PARSE("x = [1, 2, 3]"))
        assert result == {}

    def test_none_assignment_skipped(self) -> None:
        result = build_symbol_table(_PARSE("x = None"))
        assert result == {}

    def test_bool_assignment_skipped(self) -> None:
        result = build_symbol_table(_PARSE("x = True"))
        assert result == {}

    def test_empty_string_tracked(self) -> None:
        result = build_symbol_table(_PARSE("x = ''"))
        assert result == {"x": ""}

    def test_concatenation_resolved(self) -> None:
        result = build_symbol_table(_PARSE("x = 'hel' + 'lo'"))
        assert result == {"x": "hello"}

    def test_multiple_targets_skipped(self) -> None:
        """Tuple unpacking (a, b = ...) is not tracked."""
        result = build_symbol_table(_PARSE("a = b = 'val'"))
        # a = b = 'val' produces Assign with two targets -- skipped
        assert result == {}

    def test_augmented_assign_concatenates(self) -> None:
        """x += 'suffix' appends to tracked string value."""
        code = "x = 'start'\nx += 'end'"
        result = build_symbol_table(_PARSE(code))
        assert result == {"x": "startend"}


# -- R001: Function-level scoping ------------------------------------------


class TestFunctionScope:
    def test_function_local_prefixed(self) -> None:
        code = "def foo():\n    y = 'local'"
        result = build_symbol_table(_PARSE(code))
        assert result == {"foo.y": "local"}
        assert "y" not in result

    def test_module_and_function_separate(self) -> None:
        code = "x = 'module'\ndef foo():\n    y = 'local'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "module"
        assert result["foo.y"] == "local"

    def test_function_reads_module_scope(self) -> None:
        code = "x = 'module'\ndef foo():\n    y = x"
        result = build_symbol_table(_PARSE(code))
        assert result["foo.y"] == "module"

    def test_function_local_does_not_leak(self) -> None:
        """Function-level assignments must not appear at module level."""
        code = "def foo():\n    secret = 'hidden'"
        result = build_symbol_table(_PARSE(code))
        assert "secret" not in result
        assert result == {"foo.secret": "hidden"}

    def test_async_function_scoped(self) -> None:
        code = "async def bar():\n    z = 'async_val'"
        result = build_symbol_table(_PARSE(code))
        assert result == {"bar.z": "async_val"}

    def test_same_name_in_different_functions(self) -> None:
        code = "def f1():\n    x = 'a'\ndef f2():\n    x = 'b'"
        result = build_symbol_table(_PARSE(code))
        assert result["f1.x"] == "a"
        assert result["f2.x"] == "b"

    def test_function_shadows_module_variable(self) -> None:
        code = "x = 'module'\ndef foo():\n    x = 'local'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "module"
        assert result["foo.x"] == "local"


# -- R005: Variable indirection chains --------------------------------------


class TestIndirectionChains:
    def test_two_level_indirection(self) -> None:
        code = "a = 'base'\nb = a"
        result = build_symbol_table(_PARSE(code))
        assert result["b"] == "base"

    def test_three_level_indirection(self) -> None:
        code = "a = 'base'\nb = a\nc = b"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "base"
        assert result["b"] == "base"
        assert result["c"] == "base"

    def test_indirection_to_unknown_skipped(self) -> None:
        code = "x = unknown_var"
        result = build_symbol_table(_PARSE(code))
        assert result == {}

    def test_function_indirection_from_module(self) -> None:
        code = "url = 'http://evil.com'\ndef f():\n    target = url"
        result = build_symbol_table(_PARSE(code))
        assert result["f.target"] == "http://evil.com"

    def test_function_indirection_local(self) -> None:
        code = "def f():\n    a = 'val'\n    b = a"
        result = build_symbol_table(_PARSE(code))
        assert result["f.a"] == "val"
        assert result["f.b"] == "val"


# -- R-IMP001: Circular references and depth bounds ------------------------


class TestCircularAndDepth:
    def test_circular_reference_removed(self) -> None:
        code = "a = b\nb = a"
        result = build_symbol_table(_PARSE(code))
        assert "a" not in result
        assert "b" not in result

    def test_self_reference_removed(self) -> None:
        code = "x = x"
        result = build_symbol_table(_PARSE(code))
        assert "x" not in result

    def test_three_way_circular_removed(self) -> None:
        code = "a = b\nb = c\nc = a"
        result = build_symbol_table(_PARSE(code))
        assert result == {}

    def test_max_resolve_depth_is_named_constant(self) -> None:
        assert isinstance(MAX_RESOLVE_DEPTH, int)
        assert MAX_RESOLVE_DEPTH > 0

    def test_depth_limit_enforced(self) -> None:
        """Build a chain longer than MAX_RESOLVE_DEPTH and verify termination."""
        # Create a chain: v0 = 'base', v1 = v0, v2 = v1, ... v(N) = v(N-1)
        n = MAX_RESOLVE_DEPTH + 5
        lines = ["v0 = 'base'"]
        for i in range(1, n + 1):
            lines.append(f"v{i} = v{i - 1}")
        code = "\n".join(lines)
        result = build_symbol_table(_PARSE(code))
        # Early links should resolve
        assert result["v0"] == "base"
        assert result["v1"] == "base"
        # The chain terminates -- it doesn't hang or crash
        # (Some late entries may or may not resolve depending on implementation,
        # but the function must return without error)
        assert isinstance(result, dict)


# -- Internal helpers -------------------------------------------------------


class TestCollectAssignments:
    def test_returns_ref_for_name_rhs(self) -> None:
        tree = _PARSE("x = y")
        table = _collect_assignments(tree.body)
        assert isinstance(table["x"], _Ref)
        assert table["x"].target == "y"

    def test_returns_string_for_constant_rhs(self) -> None:
        tree = _PARSE("x = 'hello'")
        table = _collect_assignments(tree.body)
        assert table["x"] == "hello"


class TestResolveIndirections:
    def test_resolves_simple_ref(self) -> None:
        scope: dict[str, str | _Ref] = {"a": "val", "b": _Ref("a")}
        _resolve_indirections(scope)
        assert scope == {"a": "val", "b": "val"}

    def test_removes_circular(self) -> None:
        scope: dict[str, str | _Ref] = {"a": _Ref("b"), "b": _Ref("a")}
        _resolve_indirections(scope)
        assert scope == {}

    def test_parent_scope_lookup(self) -> None:
        parent: dict[str, str | _Ref] = {"x": "parent_val"}
        scope: dict[str, str | _Ref] = {"y": _Ref("x")}
        _resolve_indirections(scope, parent_scope=parent)
        assert scope == {"y": "parent_val"}


class TestFollowChain:
    def test_direct_string(self) -> None:
        scope: dict[str, str | _Ref] = {"a": "val"}
        assert _follow_chain("a", scope, None) == "val"

    def test_one_hop(self) -> None:
        scope: dict[str, str | _Ref] = {"a": _Ref("b"), "b": "val"}
        assert _follow_chain("a", scope, None) == "val"

    def test_circular_returns_none(self) -> None:
        scope: dict[str, str | _Ref] = {"a": _Ref("b"), "b": _Ref("a")}
        assert _follow_chain("a", scope, None) is None

    def test_unknown_target_returns_none(self) -> None:
        scope: dict[str, str | _Ref] = {"a": _Ref("missing")}
        assert _follow_chain("a", scope, None) is None
