"""Tests for function return-value tracking in the symbol table builder.

Covers build_symbol_table() return-value tracking under composite keys
('funcname()', 'ClassName.method()', 'innerfunc()'), convergent/divergent
returns, implicit fallthrough, try/except, and call-site assignment resolution.
"""

from __future__ import annotations

import ast
import pathlib

from skill_scan._ast_symbol_table import build_symbol_table

_PARSE = ast.parse


# -- R001: Single-return string constant ------------------------------------


class TestSingleReturn:
    def test_function_returning_string_constant(self) -> None:
        assert build_symbol_table(_PARSE("def f():\n    return 'hello'"))["f()"] == "hello"

    def test_function_returning_empty_string(self) -> None:
        assert build_symbol_table(_PARSE("def f():\n    return ''"))["f()"] == ""

    def test_function_returning_concatenation(self) -> None:
        assert build_symbol_table(_PARSE("def f():\n    return 'hel' + 'lo'"))["f()"] == "hello"


# -- R002: Multi-return convergent/divergent --------------------------------


class TestMultiReturn:
    def test_convergent_returns_same_string(self) -> None:
        code = "def f(x):\n    if x:\n        return 'val'\n    else:\n        return 'val'\n"
        assert build_symbol_table(_PARSE(code))["f()"] == "val"

    def test_divergent_returns_not_tracked(self) -> None:
        code = "def f(x):\n    if x:\n        return 'one'\n    else:\n        return 'two'\n"
        assert "f()" not in build_symbol_table(_PARSE(code))

    def test_convergent_three_branches(self) -> None:
        code = (
            "def f(x):\n"
            "    if x == 1:\n        return 'val'\n"
            "    elif x == 2:\n        return 'val'\n"
            "    else:\n        return 'val'\n"
        )
        assert build_symbol_table(_PARSE(code))["f()"] == "val"


# -- R003: Return path shapes (early return, try/except) --------------------


class TestReturnPathShapes:
    def test_early_return_and_final_same_value(self) -> None:
        code = "def f(x):\n    if x:\n        return 'val'\n    return 'val'\n"
        assert build_symbol_table(_PARSE(code))["f()"] == "val"

    def test_try_except_same_return(self) -> None:
        code = "def f():\n    try:\n        return 'val'\n    except Exception:\n        return 'val'\n"
        assert build_symbol_table(_PARSE(code))["f()"] == "val"

    def test_try_finally_returns(self) -> None:
        code = "def f():\n    try:\n        x = 1\n    finally:\n        return 'val'\n"
        assert build_symbol_table(_PARSE(code))["f()"] == "val"


# -- No return / bare return / non-string return ----------------------------


class TestNoReturn:
    def test_no_return_statement(self) -> None:
        assert "f()" not in build_symbol_table(_PARSE("def f():\n    x = 'hello'"))

    def test_bare_return(self) -> None:
        assert "f()" not in build_symbol_table(_PARSE("def f():\n    return"))

    def test_return_non_string(self) -> None:
        assert "f()" not in build_symbol_table(_PARSE("def f():\n    return 42"))

    def test_return_none(self) -> None:
        assert "f()" not in build_symbol_table(_PARSE("def f():\n    return None"))

    def test_return_list(self) -> None:
        assert "f()" not in build_symbol_table(_PARSE("def f():\n    return [1, 2]"))


# -- Implicit fallthrough --------------------------------------------------


class TestImplicitFallthrough:
    def test_if_without_else_has_fallthrough(self) -> None:
        code = "def f(x):\n    if x:\n        return 'val'\n"
        assert "f()" not in build_symbol_table(_PARSE(code))

    def test_some_paths_no_return(self) -> None:
        code = "def f(x):\n    if x:\n        return 'val'\n    print('no return here')\n"
        assert "f()" not in build_symbol_table(_PARSE(code))


# -- Return via tracked variable -------------------------------------------


class TestReturnVariable:
    def test_return_tracked_variable(self) -> None:
        code = "def f():\n    x = 'hello'\n    return x\n"
        assert build_symbol_table(_PARSE(code))["f()"] == "hello"

    def test_return_untracked_variable_not_tracked(self) -> None:
        assert "f()" not in build_symbol_table(_PARSE("def f(x):\n    return x\n"))

    def test_return_variable_binop(self) -> None:
        code = "def f():\n    a = 'hel'\n    b = 'lo'\n    return a + b\n"
        assert build_symbol_table(_PARSE(code))["f()"] == "hello"


# -- R006: Scope-aware keys ------------------------------------------------


class TestScopeKeys:
    def test_module_function_key(self) -> None:
        assert build_symbol_table(_PARSE("def get_name():\n    return 'eval'"))["get_name()"] == "eval"

    def test_nested_function_key(self) -> None:
        code = "def outer():\n    def inner():\n        return 'val'\n    x = 'test'\n    return x\n"
        assert build_symbol_table(_PARSE(code))["inner()"] == "val"

    def test_async_function_return(self) -> None:
        assert build_symbol_table(_PARSE("async def f():\n    return 'async_val'"))["f()"] == "async_val"


# -- R007: Class method return keys ----------------------------------------


class TestClassMethodReturns:
    def test_class_method_return(self) -> None:
        code = "class MyClass:\n    def get_name(self):\n        return 'eval'\n"
        assert build_symbol_table(_PARSE(code))["MyClass.get_name()"] == "eval"

    def test_class_static_method_return(self) -> None:
        code = "class MyClass:\n    def make():\n        return 'value'\n"
        assert build_symbol_table(_PARSE(code))["MyClass.make()"] == "value"

    def test_class_method_no_return_not_tracked(self) -> None:
        code = "class MyClass:\n    def setup(self):\n        self.x = 'hello'\n"
        result = build_symbol_table(_PARSE(code))
        assert "MyClass.setup()" not in result
        assert result["MyClass.x"] == "hello"  # self.attr still tracked


# -- R-IMP001: Existing tracking unchanged ---------------------------------


class TestExistingTrackingUnchanged:
    def test_module_variable_still_tracked(self) -> None:
        assert build_symbol_table(_PARSE("x = 'hello'"))["x"] == "hello"

    def test_function_variable_still_scoped(self) -> None:
        code = "def f():\n    x = 'local'\n    return 'val'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["f.x"] == "local"
        assert result["f()"] == "val"

    def test_class_attrs_still_tracked(self) -> None:
        code = "class C:\n    name = 'test'\n    def get(self):\n        return 'val'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["C.name"] == "test"
        assert result["C.get()"] == "val"


# -- R-IMP003: Recursive/circular safety -----------------------------------


class TestRecursiveSafety:
    def test_recursive_function_no_crash(self) -> None:
        result = build_symbol_table(_PARSE("def f():\n    return f()\n"))
        assert "f()" not in result

    def test_mutual_recursion_no_crash(self) -> None:
        code = "def a():\n    return b()\ndef b():\n    return a()\n"
        result = build_symbol_table(_PARSE(code))
        assert "a()" not in result
        assert "b()" not in result


# -- Call-site assignment resolution ----------------------------------------


class TestCallSiteAssignment:
    def test_call_site_resolves_to_return_value(self) -> None:
        code = "def get_name():\n    return 'eval'\nx = get_name()\n"
        result = build_symbol_table(_PARSE(code))
        assert result["get_name()"] == "eval"
        assert result["x"] == "eval"

    def test_call_site_method_not_resolved_at_module_level(self) -> None:
        code = "class C:\n    def get(self):\n        return 'val'\nx = C().get()\n"
        result = build_symbol_table(_PARSE(code))
        assert result["C.get()"] == "val"
        assert "x" not in result  # C().get() call too complex

    def test_call_site_unknown_function_not_resolved(self) -> None:
        assert "x" not in build_symbol_table(_PARSE("x = unknown_func()\n"))


# -- Global return resolution (PR #36 fix) ----------------------------------


class TestGlobalReturnResolution:
    def test_return_global_declared_variable(self) -> None:
        """build_symbol_table tracks return value when function returns a global-declared var."""
        code = "def f():\n    global x\n    x = 'eval'\n    return x\n"
        assert build_symbol_table(_PARSE(code))["f()"] == "eval"


# -- Match guard handling (PR #36 fix) --------------------------------------


class TestMatchGuardHandling:
    def test_guarded_wildcard_not_treated_as_exhaustive(self) -> None:
        """A case _ with a guard can fail -- function has implicit fallthrough."""
        code = (
            "def f(x):\n"
            "    match x:\n"
            "        case 1:\n"
            "            return 'val'\n"
            "        case _ if x > 0:\n"
            "            return 'val'\n"
        )
        assert "f()" not in build_symbol_table(_PARSE(code))

    def test_unguarded_wildcard_still_exhaustive(self) -> None:
        """An unguarded case _ still guarantees exhaustiveness."""
        code = (
            "def f(x):\n"
            "    match x:\n"
            "        case 1:\n"
            "            return 'val'\n"
            "        case _:\n"
            "            return 'val'\n"
        )
        assert build_symbol_table(_PARSE(code))["f()"] == "val"


# -- R-IMP005: File size constraint -----------------------------------------


class TestReturnHelperFileSize:
    def test_return_helpers_under_300_lines(self) -> None:
        src = pathlib.Path(__file__).resolve().parent.parent.parent
        target = src / "src" / "skill_scan" / "_ast_symbol_table_return_helpers.py"
        line_count = len(target.read_text().splitlines())
        assert line_count <= 300, f"_ast_symbol_table_return_helpers.py is {line_count} lines (max 300)"
