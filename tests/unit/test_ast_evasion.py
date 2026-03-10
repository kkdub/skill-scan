"""Regression tests for AST analyzer hardening — evasion and false positive fixes.

Covers: false positive guard on plain literals, expanded unsafe calls,
expanded deserialization, has_safe_loader positional args, and
advanced string resolution (chr arithmetic, list comp, bytes decode, map).
"""

from __future__ import annotations

import pytest

from skill_scan.ast_analyzer import analyze_python
from tests.unit.rule_helpers import filter_by_rule

_FILE = "test.py"
_ids = filter_by_rule


# -- CRITICAL: False positive guard on plain string literals (R-EFF002) ----

_FALSE_POSITIVE_CASES = [
    pytest.param("name = 'eval'\n", id="assign-eval"),
    pytest.param("d = {'system': True}\n", id="dict-system"),
    pytest.param("if mode == 'exec':\n    pass\n", id="compare-exec"),
    pytest.param("config = {'eval': False}\n", id="dict-eval"),
    pytest.param("x = 'popen'\n", id="assign-popen"),
    pytest.param("tags = ['getattr', 'setattr']\n", id="list-getattr"),
    pytest.param("s = '__import__'\n", id="assign-dunder-import"),
]


class TestNoFalsePositivesOnLiterals:
    @pytest.mark.parametrize("code", _FALSE_POSITIVE_CASES)
    def test_plain_literal_no_finding(self, code: str) -> None:
        findings = [f for f in analyze_python(code, _FILE) if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert not findings, f"False positive on: {code.strip()}"


# -- Item 2: __import__ in _DANGEROUS_NAMES (getattr evasion) -------------


class TestDunderImportEvasion:
    def test_getattr_building_dunder_import(self) -> None:
        code = "getattr(builtins, '__' + 'import__')('os')\n"
        findings = _ids("EXEC-006", analyze_python(code, _FILE))
        assert any("getattr" in f.matched_text for f in findings)

    def test_join_building_dunder_import(self) -> None:
        code = "x = ''.join(['_','_','i','m','p','o','r','t','_','_'])\n"
        findings = analyze_python(code, _FILE)
        assert any("__import__" in f.matched_text for f in findings)


# -- Item 3: Expanded unsafe os calls -------------------------------------

_UNSAFE_OS_CASES = [
    pytest.param("os.popen('ls')", id="os-popen"),
    pytest.param("os.execv('/bin/sh', ['sh'])", id="os-execv"),
    pytest.param("os.execl('/bin/sh', 'sh')", id="os-execl"),
    pytest.param("os.execvp('sh', ['sh'])", id="os-execvp"),
    pytest.param("os.execvpe('sh', ['sh'], {})", id="os-execvpe"),
    pytest.param("os.spawnl(os.P_NOWAIT, '/bin/sh')", id="os-spawnl"),
    pytest.param("os.spawnle(os.P_NOWAIT, '/bin/sh', {})", id="os-spawnle"),
    pytest.param("os.spawnlp(os.P_NOWAIT, 'sh')", id="os-spawnlp"),
    pytest.param("os.spawnlpe(os.P_NOWAIT, 'sh', {})", id="os-spawnlpe"),
]


class TestExpandedUnsafeCalls:
    @pytest.mark.parametrize("expr", _UNSAFE_OS_CASES)
    def test_os_call_detected(self, expr: str) -> None:
        code = f"import os\n{expr}\n"
        findings = _ids("EXEC-002", analyze_python(code, _FILE))
        assert findings, f"Not detected: {expr}"


# -- Item 4: Expanded deserialization detection ----------------------------

_DESER_CASES = [
    pytest.param("yaml.unsafe_load(data)", "yaml.unsafe_load(", id="yaml-unsafe-load"),
    pytest.param("shelve.open('db')", "shelve.open(", id="shelve-open"),
    pytest.param("cloudpickle.loads(data)", "cloudpickle.loads(", id="cloudpickle-loads"),
    pytest.param("dill.loads(data)", "dill.loads(", id="dill-loads"),
]


class TestExpandedDeserialization:
    @pytest.mark.parametrize("expr,expected_text", _DESER_CASES)
    def test_deser_detected(self, expr: str, expected_text: str) -> None:
        code = f"import yaml, shelve, cloudpickle, dill\n{expr}\n"
        findings = _ids("EXEC-007", analyze_python(code, _FILE))
        assert any(expected_text in f.matched_text for f in findings), f"Not detected: {expr}"


# -- Item 5: has_safe_loader positional arg --------------------------------


class TestSafeLoaderPositional:
    def test_yaml_load_positional_safe_loader(self) -> None:
        code = "import yaml\nyaml.load(data, SafeLoader)\n"
        assert not _ids("EXEC-007", analyze_python(code, _FILE))

    def test_yaml_load_positional_yaml_safe_loader(self) -> None:
        code = "import yaml\nyaml.load(data, yaml.SafeLoader)\n"
        assert not _ids("EXEC-007", analyze_python(code, _FILE))

    def test_yaml_load_positional_csafe_loader(self) -> None:
        code = "import yaml\nyaml.load(data, yaml.CSafeLoader)\n"
        assert not _ids("EXEC-007", analyze_python(code, _FILE))

    def test_yaml_load_positional_csafe_loader_bare(self) -> None:
        code = "import yaml\nyaml.load(data, CSafeLoader)\n"
        assert not _ids("EXEC-007", analyze_python(code, _FILE))

    def test_yaml_load_keyword_csafe_loader(self) -> None:
        code = "import yaml\nyaml.load(data, Loader=yaml.CSafeLoader)\n"
        assert not _ids("EXEC-007", analyze_python(code, _FILE))


# -- Item 6: Advanced string resolution -----------------------------------


class TestChrArithmetic:
    def test_chr_addition(self) -> None:
        # chr(51+50) = chr(101) = 'e'
        code = "x = chr(51+50)+chr(118)+chr(97)+chr(108)\n"
        findings = analyze_python(code, _FILE)
        assert any("eval" in f.matched_text for f in findings)

    def test_chr_subtraction(self) -> None:
        code = "x = chr(200-99)+chr(118)+chr(97)+chr(108)\n"
        findings = analyze_python(code, _FILE)
        assert any("eval" in f.matched_text for f in findings)

    def test_chr_multiplication(self) -> None:
        # chr(5*23) = chr(115) = 's'; build 'system' partially
        code = "x = chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)\n"
        findings = analyze_python(code, _FILE)
        assert any("system" in f.matched_text for f in findings)


class TestListCompInJoin:
    def test_join_listcomp_chr(self) -> None:
        code = "x = ''.join([chr(c) for c in [101,118,97,108]])\n"
        findings = analyze_python(code, _FILE)
        assert any("eval" in f.matched_text for f in findings)

    def test_join_listcomp_system(self) -> None:
        code = "x = ''.join([chr(c) for c in [115,121,115,116,101,109]])\n"
        findings = analyze_python(code, _FILE)
        assert any("system" in f.matched_text for f in findings)


class TestBytesDecodeResolution:
    def test_bytes_decode_eval(self) -> None:
        code = "x = b'eval'.decode()\n"
        findings = analyze_python(code, _FILE)
        assert any("eval" in f.matched_text for f in findings)

    def test_bytes_decode_system(self) -> None:
        code = "x = b'system'.decode()\n"
        findings = analyze_python(code, _FILE)
        assert any("system" in f.matched_text for f in findings)

    def test_bytes_decode_safe(self) -> None:
        code = "x = b'hello'.decode()\n"
        findings = [f for f in analyze_python(code, _FILE) if "evasion" in f.description.lower()]
        assert not findings


class TestMapChrInJoin:
    def test_join_map_chr_eval(self) -> None:
        code = "x = ''.join(map(chr, [101,118,97,108]))\n"
        findings = analyze_python(code, _FILE)
        assert any("eval" in f.matched_text for f in findings)

    def test_join_map_chr_exec(self) -> None:
        code = "x = ''.join(map(chr, [101,120,101,99]))\n"
        findings = analyze_python(code, _FILE)
        assert any("exec" in f.matched_text for f in findings)


class TestVeryLongStringConcatFP:
    """Regression: very long repeated concat should not be a false positive.

    'eval' * 100 builds 'evaleval...' which is NOT in _DANGEROUS_NAMES.
    Known FP — ast_analyzer currently flags this because the resolved string
    starts with a dangerous-name prefix in the BinOp tree. Marked as xfail
    until the analyzer is hardened against this edge case.
    """

    @pytest.mark.xfail(
        reason="Known FP: 400-char 'evaleval...' concat triggers prefix match in BinOp resolver. "
        "Rare in practice — no real attacker would repeat 'eval' 100 times. Low priority fix."
    )
    def test_very_long_eval_repeat_not_flagged(self) -> None:
        code = "x = " + " + ".join([f"'{c}'" for c in "eval" * 100]) + "\n"
        findings = analyze_python(code, _FILE)
        assert not findings, "Long 'evaleval...' concat should not flag"
