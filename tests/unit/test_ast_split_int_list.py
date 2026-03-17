"""Tests for tracked int-list comprehension resolution via parallel pre-pass.

Covers _collect_int_list_assigns pre-pass (R-IMP003) and tracked int-list
variable resolution in chr comprehension inside join (R-IMP004, R-EFF002).
Also includes acceptance scenarios for the full plan-027 feature path.
"""

from __future__ import annotations

import ast

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_int_list_helpers import _SHADOW
from skill_scan._ast_split_join_helpers import _collect_int_list_assigns
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table + int_list_table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    ilt = _collect_int_list_assigns(tree)
    return detect_split_evasion(tree, _FILE, {}, st, int_list_table=ilt)


# -- R-IMP003: _collect_int_list_assigns pre-pass ----------------------------


class TestCollectIntListAssigns:
    """Unit tests for _collect_int_list_assigns pre-pass (R-IMP003)."""

    def test_module_level_int_list(self) -> None:
        """Module-level Name = [int, int, ...] is tracked."""
        tree = _PARSE("codes = [101, 118, 97, 108]")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118, 97, 108]}

    def test_module_level_int_tuple(self) -> None:
        """Module-level Name = (int, int, ...) is tracked."""
        tree = _PARSE("codes = (101, 118, 97, 108)")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118, 97, 108]}

    def test_function_level_scoped(self) -> None:
        """Function-level assignment is scoped with function name."""
        tree = _PARSE("def f():\n    codes = [101, 118]")
        result = _collect_int_list_assigns(tree)
        assert "f.codes" in result
        assert result["f.codes"] == [101, 118]

    def test_class_method_scoped(self) -> None:
        """Class method assignment is scoped with ClassName.method."""
        tree = _PARSE("class C:\n  def m(self):\n    codes = [101]")
        result = _collect_int_list_assigns(tree)
        assert "C.m.codes" in result

    def test_mixed_type_list_shadow_marker(self) -> None:
        """Mixed list [int, str] gets _SHADOW sentinel (prevents global fallback)."""
        tree = _PARSE("codes = [101, 'hello']")
        result = _collect_int_list_assigns(tree)
        assert result["codes"] is _SHADOW

    def test_string_list_shadow_marker(self) -> None:
        """String list gets _SHADOW sentinel (prevents global fallback)."""
        tree = _PARSE("parts = ['ev', 'al']")
        result = _collect_int_list_assigns(tree)
        assert result["parts"] is _SHADOW

    def test_empty_list_tracked(self) -> None:
        """Empty list is technically all-int (vacuously true)."""
        tree = _PARSE("codes = []")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": []}

    def test_multi_target_assign_not_tracked(self) -> None:
        """Multi-target assign (a = b = [...]) is not tracked."""
        tree = _PARSE("a = b = [101, 118]")
        result = _collect_int_list_assigns(tree)
        assert len(result) == 0


# -- Control-flow recursion (red-team hardening) -----------------------------


class TestCollectIntListControlFlow:
    """Pre-pass recurses into control-flow blocks (red-team hardening)."""

    def test_if_block(self) -> None:
        """codes = [ints] inside if block is tracked."""
        tree = _PARSE("if True:\n    codes = [101, 118, 97, 108]")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118, 97, 108]}

    def test_if_else_block(self) -> None:
        """codes = [ints] inside else branch is tracked."""
        tree = _PARSE("if False:\n    pass\nelse:\n    codes = [101, 118]")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118]}

    def test_for_loop(self) -> None:
        """codes = [ints] inside for loop is tracked."""
        tree = _PARSE("for _ in range(1):\n    codes = [101, 118, 97, 108]")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118, 97, 108]}

    def test_while_loop(self) -> None:
        """codes = [ints] inside while loop is tracked."""
        tree = _PARSE("while True:\n    codes = [101, 118, 97, 108]\n    break")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118, 97, 108]}

    def test_with_block(self) -> None:
        """codes = [ints] inside with block is tracked."""
        tree = _PARSE("with open('f') as fh:\n    codes = [101, 118, 97, 108]")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118, 97, 108]}

    def test_try_block(self) -> None:
        """codes = [ints] inside try block is tracked."""
        tree = _PARSE("try:\n    codes = [101, 118, 97, 108]\nexcept:\n    pass")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118, 97, 108]}

    def test_try_except_handler(self) -> None:
        """codes = [ints] inside except handler is tracked."""
        tree = _PARSE("try:\n    pass\nexcept Exception:\n    codes = [101, 118]")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118]}

    def test_try_finally(self) -> None:
        """codes = [ints] inside finally block is tracked."""
        tree = _PARSE("try:\n    pass\nfinally:\n    codes = [101, 118]")
        result = _collect_int_list_assigns(tree)
        assert result == {"codes": [101, 118]}

    def test_nested_if_in_function(self) -> None:
        """codes = [ints] inside nested if in function is tracked with scope."""
        tree = _PARSE("def f():\n    if True:\n        codes = [101, 118]")
        result = _collect_int_list_assigns(tree)
        assert "f.codes" in result
        assert result["f.codes"] == [101, 118]

    def test_nested_control_flow_detection(self) -> None:
        """Full detection: codes inside if block resolves to EXEC-002."""
        code = "if True:\n    codes = [101, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"


# -- R-IMP004: Tracked int-list variable resolution in comprehension ---------


class TestTrackedIntListComprehension:
    """Tracked int-list variable resolves in chr comprehension (R-IMP004)."""

    def test_tracked_var_chr_comprehension_exec002(self) -> None:
        """codes = [ints]; ''.join(chr(c) for c in codes) -> EXEC-002."""
        code = "codes = [101, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_tracked_var_list_comp_exec002(self) -> None:
        """List comprehension [chr(c) for c in codes] also resolves."""
        code = "codes = [101, 118, 97, 108]\nx = ''.join([chr(c) for c in codes])"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_tracked_var_exec006_import(self) -> None:
        """Tracked var building __import__ produces EXEC-006."""
        ints = [ord(c) for c in "__import__"]
        code = f"codes = {ints!r}\nx = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-006"

    def test_tracked_var_safe_no_finding(self) -> None:
        """Tracked var building harmless string produces no finding."""
        ints = [ord(c) for c in "hello"]
        code = f"codes = {ints!r}\nx = ''.join(chr(c) for c in codes)"
        assert len(_detect(code)) == 0

    def test_tracked_var_in_function_scope(self) -> None:
        """Function-level tracked var resolves in same function scope."""
        code = "def f():\n  codes = [101, 118, 97, 108]\n  x = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_untracked_var_no_resolve(self) -> None:
        """Variable not in int_list_table does not resolve."""
        code = "x = ''.join(chr(c) for c in unknown_var)"
        assert len(_detect(code)) == 0

    def test_inline_list_still_works(self) -> None:
        """Inline int list in comprehension still resolves (regression guard)."""
        code = "x = ''.join(chr(c) for c in [101, 118, 97, 108])"
        findings = _detect(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "EXEC-002"

    def test_tracked_var_with_separator(self) -> None:
        """Tracked var with non-empty separator in join."""
        ints = [ord(c) for c in "eval"]
        code = f"codes = {ints!r}\nx = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert len(findings) >= 1

    def test_mixed_type_var_not_resolved(self) -> None:
        """Mixed-type list variable is not tracked, so comprehension does not resolve."""
        code = "codes = [101, 'x', 97]\nx = ''.join(chr(c) for c in codes)"
        assert len(_detect(code)) == 0


# -- Acceptance scenarios (plan-027 final feature path) -----------------------


class TestPlan027Acceptance:
    """Acceptance scenarios for the full plan-027 feature path."""

    def test_chained_three_way_dict_union_dangerous_kwarg(self) -> None:
        """Chained three-way dict union delivers dangerous kwarg (acceptance).

        invoke: analyze_python() on: opts = base | extra | {'shell': True};
                subprocess.run(**opts)
        expect: At least one EXEC-002 finding
        """
        code = (
            "import subprocess\n"
            "base = {'stdout': -1}\n"
            "extra = {'stderr': -1}\n"
            "opts = base | extra | {'shell': True}\n"
            "subprocess.run(**opts)"
        )
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_string_zero_is_truthy_shell_detected(self) -> None:
        """String '0' is truthy -- shell='0' detected (acceptance).

        invoke: analyze_python() on: subprocess.run(**{'shell': '0'})
        expect: EXEC-002 finding (string '0' is truthy at runtime)
        """
        code = "import subprocess\nsubprocess.run(**{'shell': '0'})"
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_tracked_int_list_chr_comprehension_resolves(self) -> None:
        """Tracked int-list variable resolves through chr comprehension (acceptance).

        invoke: analyze_python() on: codes = [101, 118, 97, 108];
                x = ''.join(chr(c) for c in codes)
        expect: EXEC-002 finding (resolves to 'eval')
        """
        code = "codes = [101, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_plus_equals_list_reassembly_detected_e2e(self) -> None:
        """Split int list via += reassembly detected end-to-end (acceptance).

        invoke: analyze_python() on: codes = [101, 118]; codes += [97, 108];
                x = ''.join(chr(c) for c in codes)
        expect: At least one EXEC-002 finding (resolves to 'eval')
        """
        code = "codes = [101, 118]\ncodes += [97, 108]\nx = ''.join(chr(c) for c in codes)"
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_extend_method_reassembly_detected_e2e(self) -> None:
        """Split int list via .extend() reassembly detected end-to-end (acceptance).

        invoke: analyze_python() on: codes = [101, 118]; codes.extend([97, 108]);
                x = ''.join(chr(c) for c in codes)
        expect: At least one EXEC-002 finding (resolves to 'eval')
        """
        code = "codes = [101, 118]\ncodes.extend([97, 108])\nx = ''.join(chr(c) for c in codes)"
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
