"""Tests for AST-based Python code analyzer.

Covers each detector with positive/negative cases, evasion variants,
safe patterns, SyntaxError fallback, and line number accuracy.
"""

from __future__ import annotations

import pytest

from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Severity
from tests.unit.rule_helpers import filter_by_rule

_FILE = "test.py"
_ids = filter_by_rule


# -- Unsafe calls: eval, exec, os.system, subprocess shell=True -----------


class TestUnsafeCalls:
    def test_detect_eval(self) -> None:
        assert any(
            f.matched_text == "eval(" for f in _ids("EXEC-002", analyze_python("eval('1+1')\n", _FILE))
        )

    def test_detect_exec(self) -> None:
        assert any(
            "exec" in f.matched_text for f in _ids("EXEC-002", analyze_python("exec('print(1)')\n", _FILE))
        )

    def test_detect_os_system(self) -> None:
        assert _ids("EXEC-002", analyze_python("import os\nos.system('rm -rf /')\n", _FILE))

    def test_detect_subprocess_shell_true(self) -> None:
        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        assert any("shell=True" in f.matched_text for f in _ids("EXEC-002", analyze_python(code, _FILE)))

    def test_subprocess_shell_false_safe(self) -> None:
        assert not _ids(
            "EXEC-002", analyze_python("import subprocess\nsubprocess.run(['ls'], shell=False)\n", _FILE)
        )

    def test_eval_severity_critical(self) -> None:
        assert all(
            f.severity == Severity.CRITICAL for f in _ids("EXEC-002", analyze_python("eval('x')\n", _FILE))
        )

    def test_eval_category(self) -> None:
        assert all(
            f.category == "malicious-code" for f in _ids("EXEC-002", analyze_python("eval('x')\n", _FILE))
        )


# -- Dynamic imports: __import__, importlib.import_module -----------------


class TestDynamicImports:
    def test_detect_dunder_import(self) -> None:
        assert _ids("EXEC-006", analyze_python("__import__('os')\n", _FILE))

    def test_detect_importlib(self) -> None:
        code = "import importlib\nimportlib.import_module('os')\n"
        assert _ids("EXEC-006", analyze_python(code, _FILE))

    def test_severity_high(self) -> None:
        assert all(
            f.severity == Severity.HIGH for f in _ids("EXEC-006", analyze_python("__import__('os')\n", _FILE))
        )


# -- Unsafe deserialization: pickle, yaml, marshal ------------------------


class TestUnsafeDeserialization:
    def test_pickle_loads(self) -> None:
        assert _ids("EXEC-007", analyze_python("import pickle\npickle.loads(data)\n", _FILE))

    def test_pickle_load(self) -> None:
        assert _ids("EXEC-007", analyze_python("import pickle\npickle.load(f)\n", _FILE))

    def test_marshal_loads(self) -> None:
        assert _ids("EXEC-007", analyze_python("import marshal\nmarshal.loads(data)\n", _FILE))

    def test_yaml_load_unsafe(self) -> None:
        assert _ids("EXEC-007", analyze_python("import yaml\nyaml.load(data)\n", _FILE))

    def test_yaml_safe_load_ok(self) -> None:
        assert not _ids("EXEC-007", analyze_python("import yaml\nyaml.safe_load(data)\n", _FILE))

    def test_yaml_load_safe_loader_ok(self) -> None:
        assert not _ids(
            "EXEC-007", analyze_python("import yaml\nyaml.load(data, Loader=SafeLoader)\n", _FILE)
        )

    def test_yaml_load_yaml_safe_loader_ok(self) -> None:
        assert not _ids(
            "EXEC-007", analyze_python("import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n", _FILE)
        )

    def test_severity_critical(self) -> None:
        assert all(
            f.severity == Severity.CRITICAL
            for f in _ids(
                "EXEC-007",
                analyze_python("import pickle\npickle.loads(data)\n", _FILE),
            )
        )


# -- String concat evasion (R-EFF001: >= 80%) ----------------------------

_EVASION_CASES = [
    pytest.param("'ev' + 'al'", id="concat-eval"),
    pytest.param("'ex' + 'ec'", id="concat-exec"),
    pytest.param("''.join(['e','v','a','l'])", id="join-eval"),
    pytest.param("''.join(['e','x','e','c'])", id="join-exec"),
    pytest.param("chr(101)+chr(118)+chr(97)+chr(108)", id="chr-eval"),
    pytest.param("chr(101)+chr(120)+chr(101)+chr(99)", id="chr-exec"),
    pytest.param("''.join([chr(101),chr(118),chr(97),chr(108)])", id="join-chr-eval"),
    pytest.param("'ev'+chr(97)+chr(108)", id="mixed-concat-chr"),
    pytest.param("'sys'+'tem'", id="concat-system"),
    pytest.param("''.join(['s','y','s','t','e','m'])", id="join-system"),
    pytest.param("chr(103)+chr(101)+chr(116)+chr(97)+chr(116)+chr(116)+chr(114)", id="chr-getattr"),
    pytest.param("'get'+'attr'", id="concat-getattr"),
]


class TestStringConcatEvasion:
    @pytest.mark.parametrize("expr", _EVASION_CASES)
    def test_evasion_detected(self, expr: str) -> None:
        findings = analyze_python(f"x = {expr}\n", _FILE)
        assert any("builds" in f.description.lower() for f in findings), f"Not detected: {expr}"

    def test_detection_rate_above_80_pct(self) -> None:
        detected = sum(
            1
            for c in _EVASION_CASES
            if any("builds" in f.description.lower() for f in analyze_python(f"x = {c.values[0]}\n", _FILE))
        )
        rate = detected / len(_EVASION_CASES)
        assert rate >= 0.80, f"Rate {rate:.0%} < 80% ({detected}/{len(_EVASION_CASES)})"


# -- Dynamic access: getattr with concat ---------------------------------


class TestDynamicAccess:
    def test_getattr_concat_eval(self) -> None:
        findings = analyze_python("getattr(__builtins__, 'ev'+'al')('1+1')\n", _FILE)
        assert any(f.rule_id == "EXEC-006" and "getattr" in f.matched_text for f in findings)

    def test_getattr_join_system(self) -> None:
        findings = analyze_python("getattr(os, ''.join(['s','y','s','t','e','m']))('ls')\n", _FILE)
        assert any(f.rule_id == "EXEC-006" and "getattr" in f.matched_text for f in findings)

    def test_getattr_safe_attribute_ok(self) -> None:
        findings = analyze_python("getattr(obj, 'name')\n", _FILE)
        assert not [f for f in findings if f.rule_id == "EXEC-006" and "getattr" in f.matched_text]


# -- Safe patterns: zero false positives (R-EFF002) -----------------------

_SAFE_PATTERNS = [
    "import ast\nresult = ast.literal_eval('[1,2,3]')\n",
    "import yaml\ndata = yaml.safe_load(content)\n",
    "import subprocess\nsubprocess.run(['ls', '-la'], shell=False)\n",
    "import subprocess\nsubprocess.run(['echo', 'hello'])\n",
    "x = 'hello' + ' world'\n",
    "items = ''.join(['a', 'b', 'c'])\n",
    "import json\ndata = json.loads(text)\n",
    "getattr(obj, 'name')\n",
]


class TestSafePatterns:
    @pytest.mark.parametrize("code", _SAFE_PATTERNS)
    def test_no_finding(self, code: str) -> None:
        dangerous = [
            f for f in analyze_python(code, _FILE) if f.rule_id in ("EXEC-002", "EXEC-006", "EXEC-007")
        ]
        assert not dangerous, f"False positive: {dangerous}"


# -- SyntaxError fallback (R007) ------------------------------------------


class TestSyntaxErrorFallback:
    def test_syntax_error_empty(self) -> None:
        assert analyze_python("def foo(\n", _FILE) == []

    def test_invalid_code_empty(self) -> None:
        assert analyze_python("}{}{not python!@#$\n", _FILE) == []

    def test_empty_string_empty(self) -> None:
        assert analyze_python("", _FILE) == []


# -- Line numbers and file path -------------------------------------------


class TestLineNumbers:
    def test_eval_on_line_3(self) -> None:
        findings = analyze_python("x = 1\ny = 2\neval('x + y')\n", _FILE)
        assert any(f.line == 3 for f in _ids("EXEC-002", findings))

    def test_multiple_findings_lines(self) -> None:
        findings = analyze_python("eval('a')\nimport pickle\npickle.loads(b'')\n", _FILE)
        assert any(f.line == 1 for f in _ids("EXEC-002", findings))
        assert any(f.line == 3 for f in _ids("EXEC-007", findings))

    def test_file_path_propagated(self) -> None:
        assert all(f.file == "my/file.py" for f in analyze_python("eval('x')\n", "my/file.py"))


# -- Finding model fields (R-IMP004) --------------------------------------


class TestFindingModel:
    def test_has_recommendation(self) -> None:
        assert all(f.recommendation for f in _ids("EXEC-002", analyze_python("eval('x')\n", _FILE)))

    def test_has_description(self) -> None:
        assert all(f.description for f in _ids("EXEC-002", analyze_python("eval('x')\n", _FILE)))

    def test_has_matched_text(self) -> None:
        assert all(f.matched_text for f in _ids("EXEC-002", analyze_python("eval('x')\n", _FILE)))
