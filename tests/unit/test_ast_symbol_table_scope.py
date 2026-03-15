"""Tests for global and nonlocal declaration handling in the symbol table.

Covers: global writes routed to module scope, nonlocal writes routed to
enclosing function scope, last-write-wins, per-function scoping, and
detection of evasion fixtures.
"""

from __future__ import annotations

import ast
import pathlib

from skill_scan._ast_symbol_table import build_symbol_table

_PARSE = ast.parse
_FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion"


# -- R003: Global declaration routing ----------------------------------------


class TestGlobalDeclaration:
    """build_symbol_table routes global-declared writes to module scope (R003)."""

    def test_global_routes_to_module_scope(self) -> None:
        """Global write overwrites module-scope value (R003)."""
        code = "x = 'eval'\ndef f():\n    global x\n    x = 'exec'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "exec"
        assert "f.x" not in result

    def test_global_no_prior_module_value(self) -> None:
        """Global write creates module-scope entry even without prior assignment."""
        code = "def f():\n    global x\n    x = 'exec'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "exec"
        assert "f.x" not in result

    def test_global_multiple_vars(self) -> None:
        """Global declaration with multiple names: global a, b."""
        code = "a = 'x'\nb = 'y'\ndef f():\n    global a, b\n    a = 'ex'\n    b = 'ec'"
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "ex"
        assert result["b"] == "ec"
        assert "f.a" not in result
        assert "f.b" not in result


# -- R005: Last-write-wins for global writes ---------------------------------


class TestGlobalLastWriteWins:
    """Global writes use last-write-wins semantics (R005)."""

    def test_two_functions_same_global(self) -> None:
        """Two functions writing to same global -- last function wins."""
        code = "x = 'a'\ndef f():\n    global x\n    x = 'b'\ndef g():\n    global x\n    x = 'c'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "c"

    def test_global_overwrites_module_assignment(self) -> None:
        """Global write takes precedence over earlier module-level assignment."""
        code = "x = 'original'\ndef f():\n    global x\n    x = 'updated'"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "updated"


# -- R-IMP006: No duplicate function-scoped key -----------------------------


class TestNoDuplicateKey:
    """Global writes must not create duplicate function-scoped key (R-IMP006)."""

    def test_function_prefixed_key_absent(self) -> None:
        code = "x = 'a'\ndef f():\n    global x\n    x = 'b'"
        result = build_symbol_table(_PARSE(code))
        assert "f.x" not in result
        assert result["x"] == "b"


# -- R-IMP007: Per-function scoping -----------------------------------------


class TestPerFunctionScoping:
    """Global/nonlocal declarations scoped per function (R-IMP007)."""

    def test_sibling_functions_different_globals(self) -> None:
        """Two sibling functions with different global vars update independently."""
        code = (
            "x = 'orig_x'\ny = 'orig_y'\n"
            "def f():\n    global x\n    x = 'new_x'\n"
            "def g():\n    global y\n    y = 'new_y'\n"
        )
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "new_x"
        assert result["y"] == "new_y"

    def test_function_without_global_stays_local(self) -> None:
        """A function without global declaration keeps local scope."""
        code = "x = 'module'\ndef f():\n    x = 'local'\ndef g():\n    global x\n    x = 'global'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "global"
        assert result["f.x"] == "local"


# -- R004: Nonlocal declaration routing --------------------------------------


class TestNonlocalDeclaration:
    """build_symbol_table routes nonlocal writes to enclosing scope (R004)."""

    def test_nonlocal_routes_to_enclosing_scope(self) -> None:
        """Nonlocal write updates enclosing function scope (R004)."""
        code = "def outer():\n    x = 'eval'\n    def inner():\n        nonlocal x\n        x = 'exec'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["outer.x"] == "exec"
        assert "inner.x" not in result

    def test_nonlocal_multiple_vars(self) -> None:
        """Nonlocal with multiple vars updates all in enclosing scope."""
        code = (
            "def outer():\n"
            "    a = 'x'\n"
            "    b = 'y'\n"
            "    def inner():\n"
            "        nonlocal a, b\n"
            "        a = 'ex'\n"
            "        b = 'ec'\n"
        )
        result = build_symbol_table(_PARSE(code))
        assert result["outer.a"] == "ex"
        assert result["outer.b"] == "ec"
        assert "inner.a" not in result
        assert "inner.b" not in result


# -- R006: Nonlocal does not affect module scope -----------------------------


class TestNonlocalDoesNotAffectModule:
    """Nonlocal writes update enclosing function scope, not module scope (R006)."""

    def test_module_scope_unchanged(self) -> None:
        """Module-level var with same name is not affected by nonlocal."""
        code = (
            "x = 'module_x'\n"
            "def outer():\n"
            "    x = 'outer_x'\n"
            "    def inner():\n"
            "        nonlocal x\n"
            "        x = 'inner_x'\n"
        )
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "module_x"
        assert result["outer.x"] == "inner_x"


# -- R-EFF003/R-EFF004: Evasion fixture detection ---------------------------


class TestEvasionFixtures:
    """Corpus fixtures trigger findings through the full analyzer."""

    def test_global_overwrite_fixture_exists(self) -> None:
        """pos_global_overwrite.py fixture file exists (R-EFF003)."""
        assert (_FIXTURES / "pos_global_overwrite.py").exists()

    def test_nonlocal_overwrite_fixture_exists(self) -> None:
        """pos_nonlocal_overwrite.py fixture file exists (R-EFF004)."""
        assert (_FIXTURES / "pos_nonlocal_overwrite.py").exists()

    def test_global_overwrite_symbol_table(self) -> None:
        """Global overwrite fixture produces correct symbol table (R-EFF003)."""
        code = (_FIXTURES / "pos_global_overwrite.py").read_text()
        result = build_symbol_table(_PARSE(code))
        assert result["a"] == "ex"
        assert result["b"] == "ec"

    def test_nonlocal_overwrite_symbol_table(self) -> None:
        """Nonlocal overwrite fixture produces correct symbol table (R-EFF004)."""
        code = (_FIXTURES / "pos_nonlocal_overwrite.py").read_text()
        result = build_symbol_table(_PARSE(code))
        assert result["outer.a"] == "ex"
        assert result["outer.b"] == "ec"


# -- Global inside control flow ----------------------------------------------


class TestGlobalInControlFlow:
    """Global/nonlocal declarations inside control-flow bodies are collected."""

    def test_global_inside_if(self) -> None:
        code = "x = 'a'\ndef f():\n    if True:\n        global x\n        x = 'b'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"
        assert "f.x" not in result

    def test_global_inside_for(self) -> None:
        code = "x = 'a'\ndef f():\n    for _ in range(1):\n        global x\n        x = 'b'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"
        assert "f.x" not in result

    def test_global_inside_while(self) -> None:
        code = "x = 'a'\ndef f():\n    while True:\n        global x\n        x = 'b'\n        break\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"

    def test_global_inside_with(self) -> None:
        code = "x = 'a'\ndef f():\n    with open('f') as _:\n        global x\n        x = 'b'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"

    def test_global_inside_try(self) -> None:
        code = "x = 'a'\ndef f():\n    try:\n        global x\n        x = 'b'\n    except:\n        pass\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"

    def test_global_inside_try_handler(self) -> None:
        code = "x = 'a'\ndef f():\n    try:\n        pass\n    except:\n        global x\n        x = 'b'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"

    def test_global_inside_try_finally(self) -> None:
        code = "x = 'a'\ndef f():\n    try:\n        pass\n    finally:\n        global x\n        x = 'b'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"

    def test_nonlocal_inside_for(self) -> None:
        code = (
            "def outer():\n"
            "    x = 'a'\n"
            "    def inner():\n"
            "        for _ in range(1):\n"
            "            nonlocal x\n"
            "            x = 'b'\n"
        )
        result = build_symbol_table(_PARSE(code))
        assert result["outer.x"] == "b"

    def test_global_inside_async_for(self) -> None:
        code = "x = 'a'\nasync def f():\n    async for _ in aiter():\n        global x\n        x = 'b'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"

    def test_global_inside_async_with(self) -> None:
        code = "x = 'a'\nasync def f():\n    async with ctx() as _:\n        global x\n        x = 'b'\n"
        result = build_symbol_table(_PARSE(code))
        assert result["x"] == "b"
