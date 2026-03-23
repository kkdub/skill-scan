"""Tests for ref_table pre-pass infrastructure (build_ref_table + RefEntry).

Tests cover:
- RefEntry dataclass structure (frozen, slots)
- build_ref_table recognizing __import__('mod') at module level
- build_ref_table recognizing importlib.import_module('mod') at module level
- build_ref_table recognizing builtins.__import__('mod')
- build_ref_table recognizing __builtins__.__import__('mod')
- Function-scoped keys (func.varname format)
- Class-scoped keys (ClassName.varname format)
- Non-import assignments ignored (no false positives)
- build_ref_table returns dict[str, RefEntry] (type contract)
- Integration via analyze_python (build_ref_table wired in)
- build_symbol_table still returns dict[str, str] (R009)
"""

from __future__ import annotations

import ast
import textwrap

from skill_scan._ast_ref_tracker import RefEntry, build_ref_table
from skill_scan._ast_imports import build_alias_map
from skill_scan._ast_symbol_table import build_symbol_table


def _build(code: str) -> dict[str, RefEntry]:
    """Parse code and return ref_table."""
    source = textwrap.dedent(code)
    tree = ast.parse(source)
    alias_map = build_alias_map(tree)
    return build_ref_table(tree, alias_map)


# ---------------------------------------------------------------------------
# RefEntry dataclass structure
# ---------------------------------------------------------------------------


class TestRefEntryDataclass:
    """RefEntry is a frozen dataclass with slots."""

    def test_frozen(self) -> None:
        """RefEntry instances are immutable."""
        entry = RefEntry(kind="module", resolved="os")
        try:
            entry.kind = "func_ref"  # type: ignore[misc]
            raised = False
        except AttributeError:
            raised = True
        assert raised, "RefEntry should be frozen"

    def test_slots(self) -> None:
        """RefEntry uses __slots__."""
        entry = RefEntry(kind="module", resolved="os")
        assert hasattr(entry, "__slots__") or not hasattr(entry, "__dict__")

    def test_fields(self) -> None:
        """RefEntry has kind and resolved fields."""
        entry = RefEntry(kind="module", resolved="subprocess")
        assert entry.kind == "module"
        assert entry.resolved == "subprocess"


# ---------------------------------------------------------------------------
# Module-level __import__ tracking
# ---------------------------------------------------------------------------


class TestDunderImport:
    """build_ref_table tracks x = __import__('mod') at module level."""

    def test_basic_dunder_import(self) -> None:
        """m = __import__('os') -> key 'm', resolved 'os'."""
        ref = _build("m = __import__('os')")
        assert "m" in ref
        assert ref["m"].kind == "module"
        assert ref["m"].resolved == "os"

    def test_dunder_import_subprocess(self) -> None:
        """mod = __import__('subprocess') -> key 'mod', resolved 'subprocess'."""
        ref = _build("mod = __import__('subprocess')")
        assert "mod" in ref
        assert ref["mod"].resolved == "subprocess"

    def test_builtins_dunder_import(self) -> None:
        """m = builtins.__import__('os') -> tracked."""
        ref = _build("import builtins\nm = builtins.__import__('os')")
        assert "m" in ref
        assert ref["m"].resolved == "os"

    def test_dunder_builtins_dunder_import(self) -> None:
        """m = __builtins__.__import__('shutil') -> tracked."""
        ref = _build("m = __builtins__.__import__('shutil')")
        assert "m" in ref
        assert ref["m"].resolved == "shutil"


# ---------------------------------------------------------------------------
# importlib.import_module tracking
# ---------------------------------------------------------------------------


class TestImportlibImportModule:
    """build_ref_table tracks x = importlib.import_module('mod')."""

    def test_basic_importlib(self) -> None:
        """mod = importlib.import_module('subprocess') -> tracked."""
        ref = _build("""\
            import importlib
            mod = importlib.import_module('subprocess')
        """)
        assert "mod" in ref
        assert ref["mod"].kind == "module"
        assert ref["mod"].resolved == "subprocess"

    def test_aliased_importlib(self) -> None:
        """il = importlib; x = il.import_module('os') -> tracked via alias_map."""
        ref = _build("""\
            import importlib as il
            x = il.import_module('os')
        """)
        assert "x" in ref
        assert ref["x"].resolved == "os"


# ---------------------------------------------------------------------------
# Function-scoped keys
# ---------------------------------------------------------------------------


class TestFunctionScope:
    """Function-scoped __import__ uses 'func.varname' key format."""

    def test_function_scoped_dunder_import(self) -> None:
        """def foo(): m = __import__('os') -> key 'foo.m'."""
        ref = _build("""\
            def foo():
                m = __import__('os')
        """)
        assert "foo.m" in ref
        assert ref["foo.m"].resolved == "os"
        assert "m" not in ref, "Module-level key should not exist for function-scoped import"

    def test_function_scoped_importlib(self) -> None:
        """def bar(): x = importlib.import_module('sys') -> key 'bar.x'."""
        ref = _build("""\
            import importlib
            def bar():
                x = importlib.import_module('sys')
        """)
        assert "bar.x" in ref
        assert ref["bar.x"].resolved == "sys"

    def test_async_function_scope(self) -> None:
        """async def baz(): m = __import__('os') -> key 'baz.m'."""
        ref = _build("""\
            async def baz():
                m = __import__('os')
        """)
        assert "baz.m" in ref
        assert ref["baz.m"].resolved == "os"


# ---------------------------------------------------------------------------
# Class-scoped keys
# ---------------------------------------------------------------------------


class TestClassScope:
    """Class body assignments use ClassName.varname key format."""

    def test_class_body_import(self) -> None:
        """Class-level __import__ uses ClassName.varname key."""
        ref = _build("""\
            class MyClass:
                m = __import__('os')
        """)
        assert "MyClass.m" in ref
        assert ref["MyClass.m"].resolved == "os"


# ---------------------------------------------------------------------------
# Non-import assignments (no false positives)
# ---------------------------------------------------------------------------


class TestNonImportAssignments:
    """Assignments that are not __import__/importlib.import_module are ignored."""

    def test_regular_assignment_ignored(self) -> None:
        """x = 'os' does not produce a ref_table entry."""
        ref = _build("x = 'os'")
        assert len(ref) == 0

    def test_regular_function_call_ignored(self) -> None:
        """x = some_func('os') does not produce a ref_table entry."""
        ref = _build("x = some_func('os')")
        assert len(ref) == 0

    def test_import_statement_not_tracked(self) -> None:
        """Regular import os does not go into ref_table (that's alias_map)."""
        ref = _build("import os")
        assert len(ref) == 0

    def test_no_first_arg_ignored(self) -> None:
        """__import__() with no args is ignored."""
        ref = _build("m = __import__()")
        assert len(ref) == 0

    def test_non_constant_arg_ignored(self) -> None:
        """__import__(var) with non-constant arg is ignored."""
        ref = _build("m = __import__(some_var)")
        assert len(ref) == 0


# ---------------------------------------------------------------------------
# Return type contract (R009)
# ---------------------------------------------------------------------------


class TestReturnTypeContract:
    """build_ref_table returns dict[str, RefEntry]; symbol_table stays dict[str, str]."""

    def test_ref_table_return_type(self) -> None:
        """build_ref_table returns a dict with RefEntry values."""
        ref = _build("m = __import__('os')")
        assert isinstance(ref, dict)
        for key, val in ref.items():
            assert isinstance(key, str)
            assert isinstance(val, RefEntry)

    def test_symbol_table_unchanged(self) -> None:
        """build_symbol_table still returns dict[str, str] (R009)."""
        code = "x = 'hello'\ny = 'world'"
        tree = ast.parse(code)
        st = build_symbol_table(tree)
        assert isinstance(st, dict)
        for key, val in st.items():
            assert isinstance(key, str)
            assert isinstance(val, str), f"symbol_table value should be str, got {type(val)}"

    def test_empty_code_returns_empty(self) -> None:
        """build_ref_table on empty source returns empty dict."""
        ref = _build("")
        assert ref == {}
