"""Tests for AugAssign and .extend() mutation tracking in int-list pre-pass.

Covers R001 (AugAssign += extends), R002 (.extend() calls extend),
R-IMP001 (non-int mutations shadow), R-IMP002 (unknown/shadowed safe),
R-EFF001 (red-team: empty-list init, nested control flow, generator args).
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


def _collect(code: str) -> dict[str, list[int]]:
    """Helper: parse code and collect int-list assignments."""
    return _collect_int_list_assigns(_PARSE(code))


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table + int_list_table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    ilt = _collect_int_list_assigns(tree)
    return detect_split_evasion(tree, _FILE, {}, st, int_list_table=ilt)


# -- R001: AugAssign (codes += [ints]) extends tracked int-list ---------------


class TestAugAssignExtend:
    """AugAssign += on tracked int-list variables."""

    def test_augassign_extends_int_list(self) -> None:
        """codes = [101, 118]; codes += [97, 108] -> combined list."""
        result = _collect("codes = [101, 118]\ncodes += [97, 108]")
        assert result == {"codes": [101, 118, 97, 108]}

    def test_augassign_function_scoped(self) -> None:
        """Function-scoped: def f(): codes = [101]; codes += [118] -> f.codes."""
        result = _collect("def f():\n  codes = [101]\n  codes += [118]")
        assert result == {"f.codes": [101, 118]}

    def test_augassign_class_method_scoped(self) -> None:
        """Class method: codes += [118] inside class method tracks correctly."""
        code = "class C:\n  def m(self):\n    codes = [101]\n    codes += [118]"
        result = _collect(code)
        assert result == {"C.m.codes": [101, 118]}

    def test_augassign_unknown_var_ignored(self) -> None:
        """AugAssign on variable not in table is ignored (no KeyError)."""
        result = _collect("codes += [97]")
        assert result == {}

    def test_augassign_non_int_shadows(self) -> None:
        """codes = [101]; codes += ['x'] converts entry to shadow marker."""
        result = _collect("codes = [101]\ncodes += ['x']")
        assert result["codes"] is _SHADOW

    def test_augassign_already_shadowed_stays(self) -> None:
        """codes = ['a']; codes += [97] keeps entry as shadow marker."""
        result = _collect("codes = ['a']\ncodes += [97]")
        assert result["codes"] is _SHADOW

    def test_augassign_with_tuple(self) -> None:
        """codes += (97, 108) also works (tuple RHS)."""
        result = _collect("codes = [101]\ncodes += (97, 108)")
        assert result == {"codes": [101, 97, 108]}

    def test_augassign_non_add_op_ignored(self) -> None:
        """Only += (Add) is handled; other ops like -= are ignored."""
        result = _collect("codes = [101]\ncodes -= [97]")
        assert result == {"codes": [101]}

    def test_augassign_non_list_rhs_shadows(self) -> None:
        """codes += some_var (not a literal list) shadows the entry."""
        result = _collect("codes = [101]\ncodes += other")
        assert result["codes"] is _SHADOW

    def test_augassign_in_if_block(self) -> None:
        """AugAssign inside control flow (if block) is tracked."""
        code = "codes = [101]\nif True:\n    codes += [118]"
        result = _collect(code)
        assert result == {"codes": [101, 118]}


# -- R002: .extend() calls extend tracked int-list ---------------------------


class TestExtendCall:
    """.extend() calls on tracked int-list variables."""

    def test_extend_basic(self) -> None:
        """codes = [101]; codes.extend([118, 97]) -> combined list."""
        result = _collect("codes = [101]\ncodes.extend([118, 97])")
        assert result == {"codes": [101, 118, 97]}

    def test_extend_function_scoped(self) -> None:
        """Function-scoped .extend() tracks correctly."""
        code = "def f():\n  codes = [101]\n  codes.extend([118])"
        result = _collect(code)
        assert result == {"f.codes": [101, 118]}

    def test_extend_class_method_scoped(self) -> None:
        """.extend() inside class method tracks with ClassName.method prefix."""
        code = "class C:\n  def m(self):\n    codes = [101]\n    codes.extend([118])"
        result = _collect(code)
        assert result == {"C.m.codes": [101, 118]}

    def test_extend_unknown_var_ignored(self) -> None:
        """.extend() on unknown variable is ignored."""
        result = _collect("codes.extend([97])")
        assert result == {}

    def test_extend_non_int_shadows(self) -> None:
        """codes.extend(['x']) converts entry to shadow marker."""
        result = _collect("codes = [101]\ncodes.extend(['x'])")
        assert result["codes"] is _SHADOW

    def test_extend_with_tuple_arg(self) -> None:
        """codes.extend((97, 108)) works with tuple argument."""
        result = _collect("codes = [101]\ncodes.extend((97, 108))")
        assert result == {"codes": [101, 97, 108]}

    def test_extend_non_list_arg_shadows(self) -> None:
        """.extend(some_var) shadows tracked entry (unresolvable mutation)."""
        result = _collect("codes = [101]\ncodes.extend(other)")
        assert result["codes"] is _SHADOW

    def test_extend_with_keywords_ignored(self) -> None:
        """.extend() with keyword args is ignored (not valid Python but safe)."""
        result = _collect("codes = [101]\ncodes.extend([118], x=1)")
        assert result == {"codes": [101]}

    def test_extend_in_control_flow(self) -> None:
        """.extend() inside for loop is tracked."""
        code = "codes = [101]\nfor _ in range(1):\n    codes.extend([118])"
        result = _collect(code)
        assert result == {"codes": [101, 118]}


# -- Integration: mutations + detection pipeline ------------------------------


class TestMutationDetection:
    """End-to-end: mutated int-lists resolve through chr comprehension."""

    def test_augassign_resolves_to_exec002(self) -> None:
        """codes = [101, 118]; codes += [97, 108]; join(chr) -> EXEC-002."""
        code = "codes = [101, 118]\ncodes += [97, 108]\nx = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert any(f.rule_id == "EXEC-002" for f in findings)

    def test_extend_resolves_to_exec002(self) -> None:
        """codes.extend([...]) result resolves through chr comprehension."""
        code = "codes = [101, 118]\ncodes.extend([97, 108])\nx = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert any(f.rule_id == "EXEC-002" for f in findings)

    def test_shadowed_mutation_no_false_positive(self) -> None:
        """Non-int mutation prevents resolution (no false positive)."""
        code = "codes = [101, 118]\ncodes += ['x']\nx = ''.join(chr(c) for c in codes)"
        assert len(_detect(code)) == 0

    def test_multi_extend_chain(self) -> None:
        """Multiple mutations chain: codes = [101]; codes += [118]; codes.extend([97, 108])."""
        code = "codes = [101]\ncodes += [118]\ncodes.extend([97, 108])\nx = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert any(f.rule_id == "EXEC-002" for f in findings)


# -- R-EFF001: Red-team regression (empty-list init, sentinel fix) ----------


class TestEmptyListInit:
    """Empty list init followed by += should track, not shadow."""

    def test_empty_init_then_augassign(self) -> None:
        """codes = []; codes += [101, 118, 97, 108] -> tracked list."""
        result = _collect("codes = []\ncodes += [101, 118, 97, 108]")
        assert result["codes"] == [101, 118, 97, 108]

    def test_empty_init_then_augassign_detects(self) -> None:
        """Empty init + += resolves to 'eval' -> EXEC-002."""
        code = "codes = []\ncodes += [101, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"
        findings = _detect(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_empty_init_then_extend(self) -> None:
        """codes = []; codes.extend([101, 118]) -> tracked list."""
        result = _collect("codes = []\ncodes.extend([101, 118])")
        assert result["codes"] == [101, 118]

    def test_empty_init_multi_step_chain(self) -> None:
        """codes = []; codes += [95]*2 + [105, ...] builds __import__ -> EXEC-006."""
        code = (
            "def f():\n"
            "    d = []\n"
            "    d += [95, 95, 105, 109, 112, 111, 114, 116, 95, 95]\n"
            "    x = ''.join(chr(c) for c in d)"
        )
        findings = analyze_python(code, _FILE)
        assert any(f.rule_id == "EXEC-006" for f in findings)

    def test_shadow_sentinel_is_identity(self) -> None:
        """Non-int assignment produces _SHADOW sentinel (identity, not value)."""
        result = _collect("codes = 'hello'")
        assert result["codes"] is _SHADOW

    def test_empty_int_list_is_not_shadow(self) -> None:
        """codes = [] produces a real empty list, not the _SHADOW sentinel."""
        result = _collect("codes = []")
        assert result["codes"] is not _SHADOW
        assert result["codes"] == []


# -- R-EFF001: Red-team adversarial patterns ---------------------------------


class TestAdversarialAugmented:
    """Red-team adversarial patterns for augmented int-list tracking."""

    def test_nested_if_augassign(self) -> None:
        """codes += inside nested if blocks is tracked."""
        code = "codes = [101, 118]\nif True:\n    if True:\n        codes += [97, 108]"
        result = _collect(code)
        assert result["codes"] == [101, 118, 97, 108]

    def test_augassign_in_while(self) -> None:
        """codes += inside while loop is tracked."""
        code = "codes = [101, 118]\nwhile True:\n    codes += [97, 108]\n    break"
        result = _collect(code)
        assert result["codes"] == [101, 118, 97, 108]

    def test_augassign_in_try_finally(self) -> None:
        """codes += inside try/finally is tracked."""
        code = (
            "codes = [101, 118]\n"
            "try:\n    codes += [97]\nexcept Exception:\n    pass\n"
            "finally:\n    codes += [108]"
        )
        result = _collect(code)
        assert result["codes"] == [101, 118, 97, 108]

    def test_mixed_augassign_and_extend(self) -> None:
        """codes = []; codes += [...]; codes.extend([...]) chains."""
        code = "codes = [101]\ncodes += [118]\ncodes.extend([97, 108])"
        result = _collect(code)
        assert result["codes"] == [101, 118, 97, 108]

    def test_extend_generator_arg_shadows(self) -> None:
        """codes.extend(x for x in [...]) shadows (unresolvable arg)."""
        code = "codes = [101, 118]\ncodes.extend(x for x in [97, 108])"
        result = _collect(code)
        assert result["codes"] is _SHADOW

    def test_reassign_after_mutation_overrides(self) -> None:
        """Reassignment after += overrides the mutated value."""
        code = (
            "codes = [101, 118]\ncodes += [97, 108]\ncodes = [104, 105]\nx = ''.join(chr(c) for c in codes)"
        )
        findings = _detect(code)
        assert len(findings) == 0  # 'hi', not 'eval'
