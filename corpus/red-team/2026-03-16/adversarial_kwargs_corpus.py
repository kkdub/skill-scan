"""Adversarial corpus for kwargs unpacking detector.

Red-team adversarial inputs targeting _kwarg_matches truthiness logic,
_extract_dict_literal type preservation, _collect_dict_assigns tracking,
and end-to-end detect_kwargs_unpacking evasion paths.

Each test case is tagged with:
- Category (truthy-evasion, falsy-evasion, structural, resolution-gap, etc.)
- Expected outcome (DETECT = should produce EXEC-002, SAFE = should produce 0)
- Evasion technique used

Run with: python -m pytest corpus/red-team/2026-03-16/adversarial_kwargs_corpus.py -v
"""

from __future__ import annotations

import ast
import json
import textwrap
from dataclasses import dataclass

from skill_scan._ast_kwargs_detector import (
    _collect_dict_assigns,
    _extract_dict_literal,
    _kwarg_matches,
    _resolve_kwargs_dict,
    detect_kwargs_unpacking,
)
from skill_scan._ast_helpers import build_alias_map
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding


_FILE = "adversarial.py"


def _detect(code: str) -> list[Finding]:
    """Parse code, build symbol table, run kwargs detector only."""
    tree = ast.parse(textwrap.dedent(code))
    alias_map = build_alias_map(tree)
    st = build_symbol_table(tree)
    return detect_kwargs_unpacking(tree, _FILE, alias_map, st)


def _detect_full(code: str) -> list[Finding]:
    """Run full analyze_python pipeline."""
    return analyze_python(textwrap.dedent(code), _FILE)


def _has_exec002(findings: list[Finding]) -> bool:
    return any(f.rule_id == "EXEC-002" for f in findings)


# ===================================================================
# CATEGORY 1: Truthy String Evasion (R-EFF001 core claim)
# These MUST be detected. Any miss = evasion.
# ===================================================================


class TestTruthyStringEvasion:
    """Truthy string values that a naive string-comparison approach would miss."""

    def test_shell_string_0_inline(self) -> None:
        """shell='0' -- THE canonical R-EFF001 case."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': '0'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='0' not detected"

    def test_shell_string_false_inline(self) -> None:
        """shell='False' -- string 'False' is truthy in Python."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 'False'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='False' not detected"

    def test_shell_string_false_lowercase(self) -> None:
        """shell='false' -- still a non-empty string = truthy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 'false'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='false' not detected"

    def test_shell_string_none(self) -> None:
        """shell='None' -- string 'None' is truthy (non-empty)."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 'None'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='None' not detected"

    def test_shell_string_empty_list(self) -> None:
        """shell='[]' -- string '[]' is truthy (non-empty)."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': '[]'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='[]' not detected"

    def test_shell_string_zero_float(self) -> None:
        """shell='0.0' -- string '0.0' is truthy (non-empty)."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': '0.0'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='0.0' not detected"

    def test_shell_string_space(self) -> None:
        """shell=' ' -- single space is a non-empty string = truthy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': ' '})"
        assert _has_exec002(_detect(code)), "EVASION: shell=' ' not detected"

    def test_shell_string_zero_char(self) -> None:
        r"""shell='\x00' -- null byte string is truthy (non-empty)."""
        code = r"import subprocess; subprocess.run(['ls'], **{'shell': '\x00'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='\\x00' not detected"

    def test_shell_string_no(self) -> None:
        """shell='no' -- string 'no' is truthy (non-empty)."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 'no'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='no' not detected"

    def test_shell_string_off(self) -> None:
        """shell='off' -- string 'off' is truthy (non-empty)."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 'off'})"
        assert _has_exec002(_detect(code)), "EVASION: shell='off' not detected"


# ===================================================================
# CATEGORY 2: Truthy Non-String Evasion
# These MUST be detected. Any miss = evasion.
# ===================================================================


class TestTruthyNonStringEvasion:
    """Non-string truthy values that must still trigger detection."""

    def test_shell_float_1(self) -> None:
        """shell=1.0 -- truthy float."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 1.0})"
        assert _has_exec002(_detect(code)), "EVASION: shell=1.0 not detected"

    def test_shell_float_negative(self) -> None:
        """shell=-1.0 -- negative float is truthy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': -1.0})"
        assert _has_exec002(_detect(code)), "EVASION: shell=-1.0 not detected"

    def test_shell_negative_int(self) -> None:
        """shell=-1 -- negative int is truthy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': -1})"
        assert _has_exec002(_detect(code)), "EVASION: shell=-1 not detected"

    def test_shell_large_int(self) -> None:
        """shell=999 -- large int is truthy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 999})"
        assert _has_exec002(_detect(code)), "EVASION: shell=999 not detected"

    def test_shell_complex_nonzero(self) -> None:
        """shell=1j -- non-zero complex is truthy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 1j})"
        assert _has_exec002(_detect(code)), "EVASION: shell=1j not detected"

    def test_shell_complex_real_only(self) -> None:
        """shell=(1+0j) -- complex with real part is truthy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': (1+0j)})"
        assert _has_exec002(_detect(code)), "EVASION: shell=(1+0j) not detected"


# ===================================================================
# CATEGORY 3: Falsy Values (must NOT be detected -- false positive check)
# ===================================================================


class TestFalsyValuesSafe:
    """Falsy values must NOT produce EXEC-002 (false positive guard)."""

    def test_shell_none_safe(self) -> None:
        """shell=None is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': None})"
        assert not _has_exec002(_detect(code)), "FALSE POSITIVE: shell=None detected"

    def test_shell_false_safe(self) -> None:
        """shell=False is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': False})"
        assert not _has_exec002(_detect(code)), "FALSE POSITIVE: shell=False detected"

    def test_shell_int_0_safe(self) -> None:
        """shell=0 is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 0})"
        assert not _has_exec002(_detect(code)), "FALSE POSITIVE: shell=0 detected"

    def test_shell_float_0_safe(self) -> None:
        """shell=0.0 is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 0.0})"
        assert not _has_exec002(_detect(code)), "FALSE POSITIVE: shell=0.0 detected"

    def test_shell_complex_0_safe(self) -> None:
        """shell=0j is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 0j})"
        assert not _has_exec002(_detect(code)), "FALSE POSITIVE: shell=0j detected"

    def test_shell_empty_string_safe(self) -> None:
        """shell='' is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': ''})"
        assert not _has_exec002(_detect(code)), "FALSE POSITIVE: shell='' detected"


# ===================================================================
# CATEGORY 4: Indirect Assignment / Tracked Dict Evasion
# Values passed via tracked dict must still be detected/rejected.
# ===================================================================


class TestTrackedDictTruthyEvasion:
    """Truthy evasion via tracked dict assignment (subscript and literal)."""

    def test_subscript_shell_string_0(self) -> None:
        """opts['shell'] = '0' then subprocess.run(**opts)."""
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = '0'
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: tracked dict shell='0'"

    def test_subscript_shell_string_false(self) -> None:
        """opts['shell'] = 'False' then subprocess.run(**opts)."""
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = 'False'
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: tracked dict shell='False'"

    def test_literal_init_shell_string_0(self) -> None:
        """opts = {'shell': '0'} then subprocess.run(**opts)."""
        code = """\
        import subprocess
        opts = {'shell': '0'}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: literal init shell='0'"

    def test_literal_init_shell_float_1(self) -> None:
        """opts = {'shell': 1.0} then subprocess.run(**opts)."""
        code = """\
        import subprocess
        opts = {'shell': 1.0}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: literal init shell=1.0"

    def test_literal_init_shell_negative_int(self) -> None:
        """opts = {'shell': -1} then subprocess.run(**opts)."""
        code = """\
        import subprocess
        opts = {'shell': -1}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: literal init shell=-1"


# ===================================================================
# CATEGORY 5: Dict Union Truthy Evasion
# Dict union must propagate truthy values correctly.
# ===================================================================


class TestDictUnionTruthyEvasion:
    """Truthy values injected via dict union operators."""

    def test_binary_union_shell_string_0(self) -> None:
        """base | {'shell': '0'} -- string '0' via union."""
        code = """\
        import subprocess
        base = {'stdout': -1}
        opts = base | {'shell': '0'}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: union with shell='0'"

    def test_aug_union_shell_string_0(self) -> None:
        """opts |= {'shell': '0'} -- string '0' via augmented union."""
        code = """\
        import subprocess
        opts = {'stdout': -1}
        opts |= {'shell': '0'}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: aug union with shell='0'"

    def test_chained_union_shell_string_false(self) -> None:
        """a | b | {'shell': 'False'} -- string 'False' via chained union."""
        code = """\
        import subprocess
        a = {'stdout': -1}
        b = {'stderr': -1}
        opts = a | b | {'shell': 'False'}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: chained union with shell='False'"

    def test_union_override_false_with_string_0(self) -> None:
        """Union overrides shell=False with shell='0' (truthy string)."""
        code = """\
        import subprocess
        base = {'shell': False}
        opts = base | {'shell': '0'}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect(code)), "EVASION: union override False with '0'"


# ===================================================================
# CATEGORY 6: Symbol Table Resolution Gap
# The symbol table stores strings only -- subscript assignments to
# non-string-constant values might get coerced.
# ===================================================================


class TestSymbolTableCoercion:
    """Symbol table stores str-only -- check if non-string values survive.

    _collect_dict_assigns stores raw values, but _lookup_symbol_table_dict
    reconstructs from the symbol table which stores STRINGS. If a value
    goes through the symbol table path, it becomes a string. '0' (string)
    is truthy, so shell='0' via symbol table SHOULD be detected, but
    shell=0 via symbol table becomes '0' too, creating a false positive.
    """

    def test_symbol_table_int_0_becomes_string_0(self) -> None:
        """When int 0 goes through symbol table, it becomes string '0'.

        This is a KNOWN gap: symbol table coerces to string, so integer 0
        becomes '0' which is truthy. This tests whether the detector gets
        the correct value via dict_assigns (raw type) or symbol_table (coerced).
        """
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = 0
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        # This SHOULD produce 0 findings (int 0 is falsy).
        # If it produces findings, the value went through symbol table
        # and was coerced to string '0' (truthy) -- a false positive.
        assert not _has_exec002(findings), (
            "FALSE POSITIVE: int 0 coerced to string '0' via symbol table"
        )

    def test_symbol_table_false_becomes_string_false(self) -> None:
        """When False goes through symbol table, it becomes string 'False'.

        String 'False' is truthy. If detection uses symbol table path
        for this value, we get a false positive.
        """
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = False
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert not _has_exec002(findings), (
            "FALSE POSITIVE: False coerced to string 'False' via symbol table"
        )

    def test_symbol_table_none_becomes_string_none(self) -> None:
        """When None goes through symbol table, it becomes string 'None'.

        String 'None' is truthy. False positive if symbol table path used.
        """
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = None
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert not _has_exec002(findings), (
            "FALSE POSITIVE: None coerced to string 'None' via symbol table"
        )


# ===================================================================
# CATEGORY 7: Structural Evasion
# Non-standard code patterns that might bypass tracking.
# ===================================================================


class TestStructuralEvasion:
    """Code structure variations that might evade detection."""

    def test_conditional_dict_assignment(self) -> None:
        """Dict assigned inside if-branch -- may not be tracked."""
        code = """\
        import subprocess
        opts = {}
        if True:
            opts['shell'] = True
        subprocess.run(['ls'], **opts)
        """
        # Conservative: may or may not detect. We just check no crash.
        _detect(code)  # Should not crash

    def test_dict_in_class_method(self) -> None:
        """Dict built inside a class method."""
        code = """\
        import subprocess
        class Runner:
            def run(self):
                opts = {'shell': True}
                subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        # Class methods are collected via _collect_dict_assigns
        # (ClassDef -> FunctionDef path). Should detect.
        assert _has_exec002(findings), "EVASION: class method dict not detected"

    def test_dict_in_nested_function(self) -> None:
        """Dict built inside a nested function."""
        code = """\
        import subprocess
        def outer():
            def inner():
                opts = {'shell': True}
                subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        # Nested functions: _collect_from_body only recurses 1 level
        # (FunctionDef in tree.body). inner() is inside outer(), so
        # _collect_dict_assigns may miss it.
        # This tests whether the scope_map + dict_assigns handles nesting.

    def test_dict_reassignment_overwrite(self) -> None:
        """Dict overwritten -- only final value should matter."""
        code = """\
        import subprocess
        opts = {'shell': True}
        opts = {'shell': False}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert not _has_exec002(findings), (
            "FALSE POSITIVE: dict reassignment should use final value"
        )

    def test_dict_reassignment_to_dangerous(self) -> None:
        """Dict overwritten from safe to dangerous."""
        code = """\
        import subprocess
        opts = {'shell': False}
        opts = {'shell': True}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert _has_exec002(findings), "EVASION: dict reassignment to True not detected"

    def test_multiple_subprocess_calls_same_dict(self) -> None:
        """Same dict used in multiple subprocess calls."""
        code = """\
        import subprocess
        opts = {'shell': True}
        subprocess.run(['ls'], **opts)
        subprocess.run(['whoami'], **opts)
        """
        findings = _detect(code)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 2, f"Expected >=2 findings, got {len(exec002)}"

    def test_tuple_unpacking_target_skipped(self) -> None:
        """Tuple unpacking target should not crash."""
        code = """\
        import subprocess
        a, b = {'shell': True}, {}
        subprocess.run(['ls'], **a)
        """
        # Tuple unpacking targets are not ast.Name, so _track_assign skips.
        # Should not crash, may or may not detect.
        _detect(code)

    def test_non_constant_key_in_dict(self) -> None:
        """Dict with non-constant key -- should skip that entry."""
        code = """\
        import subprocess
        k = 'shell'
        subprocess.run(['ls'], **{k: True})
        """
        findings = _detect(code)
        # k is a Name, not a Constant -- _extract_dict_literal skips it
        assert not _has_exec002(findings), (
            "Unexpected: non-constant key resolved (may be acceptable if improved)"
        )

    def test_bytes_value_in_dict(self) -> None:
        """shell=b'True' -- bytes literal. Is it truthy?"""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': b'True'})"
        findings = _detect(code)
        # b'True' is truthy (non-empty bytes). bool(b'True') == True.
        # _extract_dict_literal stores it as raw bytes constant.
        # _kwarg_matches: isinstance(True, bool) -> bool(b'True') -> True
        assert _has_exec002(findings), "EVASION: shell=b'True' not detected"

    def test_bytes_value_empty(self) -> None:
        """shell=b'' -- empty bytes is falsy."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': b''})"
        findings = _detect(code)
        assert not _has_exec002(findings), "FALSE POSITIVE: shell=b'' detected"


# ===================================================================
# CATEGORY 8: Import Aliasing Evasion
# Different import forms that might dodge call_name matching.
# ===================================================================


class TestImportAliasingEvasion:
    """Import aliasing tricks to evade call_name prefix matching."""

    def test_from_import_run(self) -> None:
        """from subprocess import run -- does call_name resolve?"""
        code = """\
        from subprocess import run
        run(['ls'], **{'shell': True})
        """
        findings = _detect(code)
        # build_alias_map should map 'run' -> 'subprocess.run'
        assert _has_exec002(findings), "EVASION: from-import run not detected"

    def test_from_import_popen(self) -> None:
        """from subprocess import Popen -- does call_name resolve?"""
        code = """\
        from subprocess import Popen
        Popen(['ls'], **{'shell': True})
        """
        findings = _detect(code)
        assert _has_exec002(findings), "EVASION: from-import Popen not detected"

    def test_double_alias(self) -> None:
        """import subprocess as sp; sp aliased again."""
        code = """\
        import subprocess as sp
        sp.call(['ls'], **{'shell': True})
        """
        findings = _detect(code)
        assert _has_exec002(findings), "EVASION: subprocess alias not detected"

    def test_from_import_with_alias(self) -> None:
        """from subprocess import run as r -- deeper alias."""
        code = """\
        from subprocess import run as r
        r(['ls'], **{'shell': True})
        """
        findings = _detect(code)
        assert _has_exec002(findings), "EVASION: from-import-as not detected"


# ===================================================================
# CATEGORY 9: _kwarg_matches Unit-Level Adversarial
# Direct attacks on the matching function.
# ===================================================================


class TestKwargMatchesAdversarial:
    """Direct adversarial inputs for _kwarg_matches."""

    def test_bool_subclass_value(self) -> None:
        """Bool is subclass of int. Does int(True)==1 cause issues?"""
        # In Python, True IS an int. bool(True) == True. No issue expected.
        assert _kwarg_matches({"shell": True}, "shell", True) is True

    def test_key_case_sensitivity(self) -> None:
        """'Shell' != 'shell' -- case matters."""
        assert _kwarg_matches({"Shell": True}, "shell", True) is False

    def test_key_with_whitespace(self) -> None:
        """' shell' != 'shell' -- whitespace matters."""
        assert _kwarg_matches({" shell": True}, "shell", True) is False

    def test_value_is_truthy_tuple(self) -> None:
        """tuple (1,) is truthy -- but not an AST constant in dict literal."""
        # Can't appear via _extract_dict_literal (only ast.Constant values).
        # But via manual dict, it should be truthy.
        assert _kwarg_matches({"shell": (1,)}, "shell", True) is True

    def test_value_is_truthy_list(self) -> None:
        """list [1] is truthy -- but not an AST constant."""
        assert _kwarg_matches({"shell": [1]}, "shell", True) is True

    def test_value_is_falsy_empty_tuple(self) -> None:
        """Empty tuple is falsy."""
        assert _kwarg_matches({"shell": ()}, "shell", True) is False

    def test_value_is_falsy_empty_list(self) -> None:
        """Empty list is falsy."""
        assert _kwarg_matches({"shell": []}, "shell", True) is False

    def test_value_is_falsy_empty_dict(self) -> None:
        """Empty dict is falsy."""
        assert _kwarg_matches({"shell": {}}, "shell", True) is False

    def test_value_is_truthy_nonempty_dict(self) -> None:
        """Non-empty dict is truthy."""
        assert _kwarg_matches({"shell": {"a": 1}}, "shell", True) is True

    def test_non_bool_table_entry_str_coercion(self) -> None:
        """Non-bool table entry uses str() comparison. str(True) == 'True'."""
        assert _kwarg_matches({"key": True}, "key", "True") is True

    def test_non_bool_table_entry_int_as_str(self) -> None:
        """Non-bool table entry: str(1) == '1'."""
        assert _kwarg_matches({"key": 1}, "key", "1") is True

    def test_non_bool_table_entry_none_as_str(self) -> None:
        """Non-bool table entry: str(None) == 'None'."""
        assert _kwarg_matches({"key": None}, "key", "None") is True


# ===================================================================
# CATEGORY 10: Full Pipeline -- Truthy Values via analyze_python
# Ensures full pipeline (not just kwargs detector) handles these.
# ===================================================================


class TestFullPipelineTruthyEvasion:
    """End-to-end via analyze_python for truthy string evasion."""

    def test_full_pipeline_shell_string_0(self) -> None:
        """Full pipeline: shell='0' must produce EXEC-002."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': '0'})"
        assert _has_exec002(_detect_full(code)), "EVASION: full pipeline shell='0'"

    def test_full_pipeline_shell_string_false(self) -> None:
        """Full pipeline: shell='False' must produce EXEC-002."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 'False'})"
        assert _has_exec002(_detect_full(code)), "EVASION: full pipeline shell='False'"

    def test_full_pipeline_shell_float_1(self) -> None:
        """Full pipeline: shell=1.0 must produce EXEC-002."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': 1.0})"
        assert _has_exec002(_detect_full(code)), "EVASION: full pipeline shell=1.0"

    def test_full_pipeline_shell_negative_int(self) -> None:
        """Full pipeline: shell=-1 must produce EXEC-002."""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': -1})"
        assert _has_exec002(_detect_full(code)), "EVASION: full pipeline shell=-1"

    def test_full_pipeline_tracked_dict_string_0(self) -> None:
        """Full pipeline: tracked dict with shell='0'."""
        code = """\
        import subprocess
        opts = {'shell': '0'}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect_full(code)), "EVASION: full pipeline tracked '0'"

    def test_full_pipeline_union_string_0(self) -> None:
        """Full pipeline: union delivers shell='0'."""
        code = """\
        import subprocess
        base = {}
        opts = base | {'shell': '0'}
        subprocess.run(['ls'], **opts)
        """
        assert _has_exec002(_detect_full(code)), "EVASION: full pipeline union '0'"


# ===================================================================
# CATEGORY 11: _extract_dict_literal Type Preservation
# Verify raw types are preserved, not coerced.
# ===================================================================


class TestExtractDictLiteralTypePreservation:
    """_extract_dict_literal must store raw Python types, not strings."""

    def test_none_preserved_not_string(self) -> None:
        node = ast.parse("{'shell': None}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] is None
        assert not isinstance(result["shell"], str)

    def test_false_preserved_not_string(self) -> None:
        node = ast.parse("{'shell': False}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] is False
        assert isinstance(result["shell"], bool)

    def test_int_0_preserved_not_string(self) -> None:
        node = ast.parse("{'shell': 0}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] == 0
        assert isinstance(result["shell"], int)
        assert not isinstance(result["shell"], bool)

    def test_float_0_preserved(self) -> None:
        node = ast.parse("{'shell': 0.0}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] == 0.0
        assert isinstance(result["shell"], float)

    def test_string_0_is_string(self) -> None:
        node = ast.parse("{'shell': '0'}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] == "0"
        assert isinstance(result["shell"], str)

    def test_bytes_preserved(self) -> None:
        node = ast.parse("{'shell': b'yes'}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] == b"yes"
        assert isinstance(result["shell"], bytes)

    def test_complex_preserved(self) -> None:
        node = ast.parse("{'shell': 1j}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        assert result is not None
        assert result["shell"] == 1j
        assert isinstance(result["shell"], complex)

    def test_negative_int_preserved(self) -> None:
        """Negative int -1: ast.UnaryOp(USub, Constant(1))."""
        node = ast.parse("{'shell': -1}").body[0].value  # type: ignore[attr-defined]
        result = _extract_dict_literal(node)
        # ast.parse("{'shell': -1}") produces:
        # - Python 3.12+: ast.Constant(value=-1) (folded)
        # - Earlier: ast.UnaryOp(USub, Constant(1))
        # _extract_dict_literal only handles ast.Constant values.
        # If -1 is folded into Constant(-1), it works. If not, it's skipped.
        # This test validates the current behavior.
        if result and "shell" in result:
            assert result["shell"] == -1


# ===================================================================
# CATEGORY 12: Resolution Path Priority
# Symbol table vs dict_assigns -- which path wins?
# ===================================================================


class TestResolutionPathPriority:
    """Test which resolution path (_collect_dict_assigns vs symbol table) wins.

    The kwargs detector checks dict_assigns FIRST (via _resolve_kwargs_dict),
    which preserves native types. The symbol table path stores strings only.
    If dict_assigns is preferred, native types are correct. If symbol table
    is preferred, type coercion occurs.
    """

    def test_dict_assigns_preferred_over_symbol_table(self) -> None:
        """Dict assigns path preserves int 0 as falsy (no finding)."""
        code = """\
        import subprocess
        opts = {'shell': 0}
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        # If dict_assigns path wins, shell=0 (int, falsy) -> no finding
        # If symbol_table path wins, shell='0' (str, truthy) -> finding
        assert not _has_exec002(findings), (
            "FALSE POSITIVE: symbol table path coerced int 0 to string '0'"
        )

    def test_symbol_table_subscript_int_0_no_false_positive(self) -> None:
        """Subscript assignment opts['shell'] = 0 -- int 0 must stay falsy."""
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = 0
        subprocess.run(['ls'], **opts)
        """
        findings = _detect(code)
        assert not _has_exec002(findings), (
            "FALSE POSITIVE: subscript int 0 coerced to '0'"
        )


# ===================================================================
# CATEGORY 13: Negative Int via AST (UnaryOp Folding)
# Python 3.12+ folds -1 to Constant(-1), but earlier versions
# produce UnaryOp(USub, Constant(1)).
# ===================================================================


class TestNegativeIntASTParsing:
    """Negative integers and how AST represents them."""

    def test_negative_int_in_inline_dict_detected(self) -> None:
        """Inline dict {'shell': -1} -- is -1 an ast.Constant?"""
        code = "import subprocess; subprocess.run(['ls'], **{'shell': -1})"
        # Parse and check AST structure
        tree = ast.parse(code)
        # Find the Dict node
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for v in node.values:
                    if isinstance(v, ast.Constant):
                        # Folded: -1 is directly a Constant
                        pass
                    elif isinstance(v, ast.UnaryOp):
                        # Not folded: UnaryOp(USub, Constant(1))
                        # _extract_dict_literal won't handle this
                        pass
        findings = _detect(code)
        # Whether this detects depends on AST folding behavior
        # On Python 3.12+, -1 is folded to Constant(-1), so detected.
        # On earlier, UnaryOp is not a Constant, so value is skipped.

    def test_negative_int_subscript_tracked(self) -> None:
        """opts['shell'] = -1 -- subscript assignment with negative int."""
        code = """\
        import subprocess
        opts = {}
        opts['shell'] = -1
        subprocess.run(['ls'], **opts)
        """
        # _track_subscript_assign checks isinstance(value, ast.Constant)
        # On 3.12+: value.value = -1 (Constant), so tracked
        # On earlier: value = UnaryOp, so not tracked
        findings = _detect(code)
        # On 3.12+, -1 is truthy int -> should detect


# ===================================================================
# CATEGORY 14: Edge Cases
# ===================================================================


class TestEdgeCases:
    """Miscellaneous edge cases."""

    def test_empty_code(self) -> None:
        """Empty source code should not crash."""
        findings = _detect("")
        assert len(findings) == 0

    def test_no_imports(self) -> None:
        """subprocess.run without import -- call_name may not resolve."""
        code = "subprocess.run(['ls'], **{'shell': True})"
        findings = _detect(code)
        # Without import, call_name = 'subprocess.run' still works
        # because get_call_name reads attribute access directly.
        assert _has_exec002(findings), "Unexpected: no detection without import"

    def test_deeply_nested_dict_union(self) -> None:
        """Deeply nested dict unions should not crash."""
        # Build: opts = {} | {} | {} | ... | {'shell': True}
        parts = ["{}"] * 20 + ["{'shell': True}"]
        expr = " | ".join(parts)
        code = f"import subprocess\nopts = {expr}\nsubprocess.run(['ls'], **opts)"
        findings = _detect(code)
        # Deep chain: _resolve_dict_operand recurses. Should work.
        assert _has_exec002(findings), "EVASION: deep union chain not detected"

    def test_dict_with_only_non_constant_entries(self) -> None:
        """Dict where ALL entries are non-constant."""
        code = "import subprocess; subprocess.run(['ls'], **{k: v})"
        findings = _detect(code)
        assert len(findings) == 0

    def test_mixed_kwargs_and_named(self) -> None:
        """Both named shell=False and **{'shell': True} in same call."""
        code = "import subprocess; subprocess.run(['ls'], shell=False, **{'shell': True})"
        findings = _detect(code)
        # The kwargs detector only looks at ** keywords. Named kwarg
        # shell=False is separate. The ** dict has shell=True.
        # Actual Python would raise TypeError (duplicate keyword), but
        # the detector should still flag the ** dict.
        assert _has_exec002(findings), "EVASION: ** kwarg with shell=True not flagged"

    def test_star_args_not_confused_with_kwargs(self) -> None:
        """*args should not be processed as **kwargs."""
        code = "import subprocess; subprocess.run(*['ls', '--help'])"
        findings = _detect(code)
        assert len(findings) == 0

    def test_multiple_star_star_args(self) -> None:
        """Multiple ** unpacking in same call."""
        code = """\
        import subprocess
        a = {'stdout': -1}
        b = {'shell': True}
        subprocess.run(['ls'], **a, **b)
        """
        findings = _detect(code)
        # Both a and b are checked. b has shell=True.
        assert _has_exec002(findings), "EVASION: second ** arg not checked"
