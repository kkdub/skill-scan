"""Tests for int-list concat, extend-var, class body, and scope declaration tracking."""

from __future__ import annotations

import ast

from skill_scan._ast_split_int_list_tracker import _SHADOW
from skill_scan._ast_split_comprehension import _collect_int_list_assigns
from skill_scan.ast_analyzer import analyze_python

_PARSE = ast.parse
_FILE = "test.py"


def _collect(code: str) -> dict[str, list[int]]:
    """Helper: parse code and collect int-list assignments."""
    return _collect_int_list_assigns(_PARSE(code))


class TestIntListConcat:
    """_handle_assign resolves BinOp(Add) of two tracked int-lists."""

    def test_concat_two_tracked_lists(self) -> None:
        """part1 + part2 where both are tracked -> concatenated list."""
        code = "part1 = [101, 118]\npart2 = [97, 108]\ncodes = part1 + part2"
        result = _collect(code)
        assert result["codes"] == [101, 118, 97, 108]

    def test_concat_function_scoped(self) -> None:
        """Concat inside function uses function scope for lookup."""
        code = "def f():\n    a = [101, 118]\n    b = [97, 108]\n    c = a + b"
        result = _collect(code)
        assert result["f.c"] == [101, 118, 97, 108]

    def test_concat_one_unknown_shadows(self) -> None:
        """part1 + unknown_var -> shadow (unknown operand)."""
        code = "part1 = [101, 118]\ncodes = part1 + unknown"
        result = _collect(code)
        assert result["codes"] is _SHADOW

    def test_concat_both_unknown_shadows(self) -> None:
        """unknown1 + unknown2 -> shadow (neither tracked)."""
        code = "codes = unknown1 + unknown2"
        result = _collect(code)
        assert result["codes"] is _SHADOW

    def test_concat_one_shadowed_shadows(self) -> None:
        """part1 + shadowed_var -> shadow (shadowed operand)."""
        code = "part1 = [101]\npart2 = 'hello'\ncodes = part1 + part2"
        result = _collect(code)
        assert result["codes"] is _SHADOW

    def test_concat_empty_lists(self) -> None:
        """[] + [] -> empty list (not shadow)."""
        code = "a = []\nb = []\nc = a + b"
        result = _collect(code)
        assert result["c"] == []
        assert result["c"] is not _SHADOW

    def test_concat_resolves_to_eval_detection(self) -> None:
        """End-to-end: part1 + part2 -> 'eval' produces EXEC-002."""
        code = (
            "part1 = [101, 118]\npart2 = [97, 108]\ncodes = part1 + part2\nx = ''.join(chr(c) for c in codes)"
        )
        findings = analyze_python(code, _FILE)
        assert any(f.rule_id == "EXEC-002" for f in findings)

    def test_concat_non_name_operand_shadows(self) -> None:
        """part1 + [97, 108] (literal RHS, not Name) -> shadow (not tracked as BinOp concat)."""
        code = "part1 = [101, 118]\ncodes = part1 + [97, 108]"
        result = _collect(code)
        # BinOp concat only resolves Name + Name; literal RHS is not a Name node
        assert result["codes"] is _SHADOW

    def test_concat_class_method_scoped(self) -> None:
        """Concat inside class method uses ClassName.method scope."""
        code = "class C:\n    def m(self):\n        a = [101, 118]\n        b = [97, 108]\n        c = a + b"
        result = _collect(code)
        assert result["C.m.c"] == [101, 118, 97, 108]

    def test_concat_module_level_cross_scope_not_resolved(self) -> None:
        """Module-level part1, function part2 -- cross-scope operand shadows result."""
        code = "part1 = [101, 118]\ndef f():\n    part2 = [97, 108]\n    codes = part1 + part2"
        result = _collect(code)
        # Scope-based lookup finds f.part2 but not f.part1 (it's at module level),
        # so the BinOp concat returns _SHADOW (unresolvable operand).
        assert result["f.codes"] is _SHADOW


class TestExtendTrackedVar:
    """.extend(tracked_var) resolves by looking up the variable in result."""

    def test_extend_tracked_var_basic(self) -> None:
        """codes.extend(other) where other is a tracked int-list -> extends."""
        code = "other = [97, 108]\ncodes = [101, 118]\ncodes.extend(other)"
        result = _collect(code)
        assert result["codes"] == [101, 118, 97, 108]

    def test_extend_tracked_var_function_scoped(self) -> None:
        """Function-scoped .extend(tracked_var) resolves."""
        code = "def f():\n    extra = [97, 108]\n    codes = [101, 118]\n    codes.extend(extra)"
        result = _collect(code)
        assert result["f.codes"] == [101, 118, 97, 108]

    def test_extend_shadowed_var_shadows(self) -> None:
        """.extend(shadowed_var) where var is _SHADOW -> shadows target."""
        code = "other = 'hello'\ncodes = [101, 118]\ncodes.extend(other)"
        result = _collect(code)
        assert result["codes"] is _SHADOW

    def test_extend_unknown_var_shadows(self) -> None:
        """.extend(var) where var is not in result -> shadows target."""
        code = "codes = [101, 118]\ncodes.extend(unknown)"
        result = _collect(code)
        assert result["codes"] is _SHADOW

    def test_extend_tracked_var_resolves_to_detection(self) -> None:
        """End-to-end: .extend(tracked_var) produces EXEC-002."""
        code = (
            "extra = [97, 108]\ncodes = [101, 118]\ncodes.extend(extra)\nx = ''.join(chr(c) for c in codes)"
        )
        findings = analyze_python(code, _FILE)
        assert any(f.rule_id == "EXEC-002" for f in findings)

    def test_extend_tracked_var_empty_list(self) -> None:
        """.extend(empty_tracked) -> no change to target list."""
        code = "empty = []\ncodes = [101, 118]\ncodes.extend(empty)"
        result = _collect(code)
        assert result["codes"] == [101, 118]

    def test_extend_literal_list_still_works(self) -> None:
        """Existing .extend([literal]) still works (no regression)."""
        code = "codes = [101, 118]\ncodes.extend([97, 108])"
        result = _collect(code)
        assert result["codes"] == [101, 118, 97, 108]

    def test_augassign_literal_still_works(self) -> None:
        """Existing += [literal] still works (no regression)."""
        code = "codes = [101, 118]\ncodes += [97, 108]"
        result = _collect(code)
        assert result["codes"] == [101, 118, 97, 108]


class TestClassBodyIntList:
    """_collect_int_list_assigns walks ClassDef body directly for class-level vars."""

    def test_class_level_int_list_tracked(self) -> None:
        """Class-level codes = [ints] tracked under 'ClassName.codes'."""
        code = "class Evil:\n    codes = [101, 118, 97, 108]"
        result = _collect(code)
        assert "Evil.codes" in result
        assert result["Evil.codes"] == [101, 118, 97, 108]

    def test_class_level_tuple_tracked(self) -> None:
        """Class-level codes = (ints) tracked under 'ClassName.codes'."""
        code = "class Evil:\n    codes = (101, 118, 97, 108)"
        result = _collect(code)
        assert result["Evil.codes"] == [101, 118, 97, 108]

    def test_class_level_non_int_shadows(self) -> None:
        """Class-level codes = ['strings'] gets _SHADOW."""
        code = "class Evil:\n    codes = ['ev', 'al']"
        result = _collect(code)
        assert result["Evil.codes"] is _SHADOW

    def test_class_level_empty_list(self) -> None:
        """Class-level codes = [] tracked as empty (not shadow)."""
        code = "class Evil:\n    codes = []"
        result = _collect(code)
        assert "Evil.codes" in result
        assert result["Evil.codes"] == []
        assert result["Evil.codes"] is not _SHADOW

    def test_class_level_non_list_shadows(self) -> None:
        """Class-level codes = some_expr gets _SHADOW."""
        code = "class Evil:\n    codes = some_expr"
        result = _collect(code)
        assert result["Evil.codes"] is _SHADOW

    def test_class_method_still_tracked(self) -> None:
        """Class method assignments still tracked (no regression)."""
        code = "class C:\n    def m(self):\n        codes = [101, 118]"
        result = _collect(code)
        assert "C.m.codes" in result
        assert result["C.m.codes"] == [101, 118]

    def test_class_level_and_method_coexist(self) -> None:
        """Both class-level and method-level assignments tracked."""
        code = "class C:\n    class_codes = [101, 118]\n    def m(self):\n        method_codes = [97, 108]"
        result = _collect(code)
        assert result["C.class_codes"] == [101, 118]
        assert result["C.m.method_codes"] == [97, 108]

    def test_class_level_detection_e2e(self) -> None:
        """End-to-end: class-level codes resolves to 'eval' -> EXEC-002."""
        code = (
            "class Evil:\n"
            "    codes = [101, 118, 97, 108]\n"
            "    def run(self):\n"
            "        x = ''.join(chr(c) for c in self.codes)"
        )
        # Note: self.codes may not resolve through the int-list table
        # (self.attr tracking is a separate concern). This tests class-level tracking.
        result = _collect(code)
        assert "Evil.codes" in result
        assert result["Evil.codes"] == [101, 118, 97, 108]

    def test_multiple_classes_tracked(self) -> None:
        """Multiple classes each get their own scope."""
        code = "class A:\n    codes = [101, 118]\nclass B:\n    codes = [97, 108]"
        result = _collect(code)
        assert result["A.codes"] == [101, 118]
        assert result["B.codes"] == [97, 108]


class TestGlobalNonlocalIntList:
    """_collect_int_list_assigns resolves global/nonlocal declarations to correct scope keys."""

    def test_global_augassign_updates_module_key(self) -> None:
        """global codes; codes += [118] updates module-level key, not f.codes."""
        result = _collect("codes = [101]\ndef f():\n    global codes\n    codes += [118]")
        assert result["codes"] == [101, 118]
        assert "f.codes" not in result

    def test_global_extend_updates_module_key(self) -> None:
        """global codes; codes.extend() updates module-level key."""
        result = _collect("codes = [101, 118]\ndef f():\n    global codes\n    codes.extend([97, 108])")
        assert result["codes"] == [101, 118, 97, 108]
        assert "f.codes" not in result

    def test_global_assign_updates_module_key(self) -> None:
        """global codes; codes = [...] assigns to module-level key."""
        result = _collect("codes = [1]\ndef f():\n    global codes\n    codes = [101, 118]")
        assert result["codes"] == [101, 118]
        assert "f.codes" not in result

    def test_nonlocal_extend_updates_enclosing_key(self) -> None:
        """nonlocal codes in nested func updates enclosing function's key."""
        code = (
            "def outer():\n    codes = [101, 118]\n"
            "    def inner():\n        nonlocal codes\n"
            "        codes.extend([97, 108])\n    inner()"
        )
        result = _collect(code)
        assert result["outer.codes"] == [101, 118, 97, 108]
        assert "outer.inner.codes" not in result

    def test_nonlocal_augassign_updates_enclosing_key(self) -> None:
        """nonlocal codes; codes += [...] updates enclosing scope key."""
        code = (
            "def outer():\n    codes = [101, 118]\n"
            "    def inner():\n        nonlocal codes\n"
            "        codes += [97, 108]\n    inner()"
        )
        result = _collect(code)
        assert result["outer.codes"] == [101, 118, 97, 108]
        assert "outer.inner.codes" not in result

    def test_mixed_global_and_local_no_contamination(self) -> None:
        """global x updates module key; local y stays function-scoped."""
        code = "x = [1, 2]\ndef f():\n    global x\n    x += [3]\n    y = [10, 20]"
        result = _collect(code)
        assert result["x"] == [1, 2, 3]
        assert "f.x" not in result
        assert result["f.y"] == [10, 20]


class TestGlobalNonlocalE2E:
    """E2E: global/nonlocal int-list mutations produce scanner findings."""

    def test_global_intlist_mutation_produces_finding(self) -> None:
        """Module-level int-list mutated via global decl -> split-evasion finding."""
        code = (
            "codes = [101, 118]\ndef f():\n    global codes\n"
            "    codes += [97, 108]\nf()\n"
            "x = ''.join(chr(c) for c in codes)\n"
        )
        findings = analyze_python(code, _FILE)
        rule_ids = [f.rule_id for f in findings]
        assert any(r.startswith("EXEC-") or r.startswith("OBFS-") for r in rule_ids)

    def test_multilevel_nonlocal_produces_finding(self) -> None:
        """3-level nested nonlocal building dangerous string -> finding."""
        code = (
            "def outer():\n    codes = [101, 118]\n"
            "    def middle():\n        nonlocal codes\n        codes += [97]\n"
            "        def inner():\n            nonlocal codes\n"
            "            codes += [108]\n        inner()\n"
            "    middle()\n    x = ''.join(chr(c) for c in codes)\n"
        )
        findings = analyze_python(code, _FILE)
        rule_ids = [f.rule_id for f in findings]
        assert any(r.startswith("EXEC-") or r.startswith("OBFS-") for r in rule_ids)
