"""Tests for scope-declaration-aware int-list concat, extend, and child_enc fixes."""

from __future__ import annotations

import ast

from skill_scan._ast_split_comprehension import _collect_int_list_assigns
from skill_scan.ast_analyzer import analyze_python

_PARSE = ast.parse
_FILE = "test.py"


def _collect(code: str) -> dict[str, list[int]]:
    return _collect_int_list_assigns(_PARSE(code))


class TestGlobalBinopConcat:
    """_resolve_binop_concat respects global declarations for operand lookup."""

    def test_global_concat_both_operands(self) -> None:
        """global a, b; codes = a + b resolves both operands at module level."""
        code = "a = [101, 118]\nb = [97, 108]\ndef f():\n    global a, b\n    codes = a + b"
        result = _collect(code)
        assert result["f.codes"] == [101, 118, 97, 108]

    def test_global_concat_e2e(self) -> None:
        """End-to-end: global concat produces finding."""
        code = (
            "a = [101, 118]\nb = [97, 108]\ndef f():\n    global a, b\n"
            "    codes = a + b\n    x = ''.join(chr(c) for c in codes)\nf()\n"
        )
        findings = analyze_python(code, _FILE)
        assert any(f.rule_id == "EXEC-002" for f in findings)


class TestGlobalExtendVar:
    """_extend_with_tracked_var respects global declarations for source lookup."""

    def test_global_extend_tracked_var(self) -> None:
        """global extra; codes.extend(extra) resolves extra at module level."""
        code = (
            "extra = [97, 108]\ndef f():\n    global extra\n    codes = [101, 118]\n    codes.extend(extra)"
        )
        result = _collect(code)
        assert result["f.codes"] == [101, 118, 97, 108]

    def test_global_augassign_tracked_var(self) -> None:
        """global extra; codes += extra resolves extra at module level."""
        code = "extra = [97, 108]\ndef f():\n    global extra\n    codes = [101, 118]\n    codes += extra"
        result = _collect(code)
        assert result["f.codes"] == [101, 118, 97, 108]


class TestMixedNonlocalLocalChildEnc:
    """_collect_fn_body uses per-nested-function child_enc, not blanket."""

    def test_parent_nonlocal_child_local_resolves(self) -> None:
        """Parent has nonlocal y + local codes; child nonlocal codes -> parent scope."""
        code = (
            "def outer():\n    y = [1]\n    codes = [101, 118]\n"
            "    def middle():\n        nonlocal y\n        y += [2]\n"
            "        codes = [97, 108]\n"
            "        def inner():\n            nonlocal codes\n"
            "            codes += [33]\n        inner()\n    middle()\n"
        )
        result = _collect(code)
        # inner's nonlocal codes -> middle.codes (locally bound), not outer.codes
        assert result.get("outer.middle.codes") == [97, 108, 33]

    def test_pure_passthrough_still_works(self) -> None:
        """Parent has nonlocal codes; child nonlocal codes -> pass-through to outer."""
        code = (
            "def outer():\n    codes = [101, 118]\n"
            "    def middle():\n        nonlocal codes\n        codes += [97]\n"
            "        def inner():\n            nonlocal codes\n"
            "            codes += [108]\n        inner()\n"
            "    middle()\n"
        )
        result = _collect(code)
        # Multi-level chain: all resolve to outer.codes
        assert result["outer.codes"] == [101, 118, 97, 108]

    def test_transparent_intermediate_passthrough(self) -> None:
        """Middle doesn't touch x at all; inner nonlocal x -> outer scope."""
        code = (
            "def outer():\n    x = [101, 118]\n"
            "    def middle():\n"
            "        y = [1, 2]\n"
            "        def inner():\n            nonlocal x\n"
            "            x += [97, 108]\n        inner()\n"
            "    middle()\n"
        )
        result = _collect(code)
        # middle is transparent for x -- inner's nonlocal x routes to outer.x
        assert result["outer.x"] == [101, 118, 97, 108]
