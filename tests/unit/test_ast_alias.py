"""Tests for import-alias tracking in the AST pipeline.

Covers: build_alias_map(), get_call_name() with alias resolution,
alias threading through analyze_python() and all _detect_* functions.
"""

from __future__ import annotations

import ast

import pytest

from skill_scan._ast_helpers import build_alias_map, get_call_name
from skill_scan.ast_analyzer import analyze_python
from tests.unit.rule_helpers import filter_by_rule

_FILE = "test.py"
_ids = filter_by_rule


# ---------------------------------------------------------------------------
# build_alias_map
# ---------------------------------------------------------------------------


class TestBuildAliasMap:
    def test_import_with_alias(self) -> None:
        tree = ast.parse("import codecs as c\n")
        assert build_alias_map(tree) == {"c": "codecs"}

    def test_import_without_alias(self) -> None:
        tree = ast.parse("import os\n")
        assert build_alias_map(tree) == {"os": "os"}

    def test_import_from_with_alias(self) -> None:
        tree = ast.parse("from os import path as p\n")
        assert build_alias_map(tree) == {"p": "os.path"}

    def test_import_from_without_alias(self) -> None:
        tree = ast.parse("from os import path\n")
        assert build_alias_map(tree) == {"path": "os.path"}

    def test_multiple_imports(self) -> None:
        code = "import codecs as c\nimport os\nfrom pickle import loads as pl\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"c": "codecs", "os": "os", "pl": "pickle.loads"}

    def test_empty_module(self) -> None:
        assert build_alias_map(ast.parse("")) == {}

    def test_no_imports(self) -> None:
        assert build_alias_map(ast.parse("x = 1\ny = 2\n")) == {}

    def test_multiple_names_in_one_import(self) -> None:
        tree = ast.parse("import os, sys\n")
        assert build_alias_map(tree) == {"os": "os", "sys": "sys"}

    def test_multiple_names_in_from_import(self) -> None:
        tree = ast.parse("from os import path, getcwd\n")
        assert build_alias_map(tree) == {"path": "os.path", "getcwd": "os.getcwd"}

    def test_nested_import_ignored(self) -> None:
        """Imports inside functions/classes must not leak into the module alias map."""
        code = "import os\ndef f():\n    import json as os\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"os": "os"}


# ---------------------------------------------------------------------------
# get_call_name with alias_map
# ---------------------------------------------------------------------------


class TestGetCallNameWithAlias:
    def test_simple_name_no_alias(self) -> None:
        tree = ast.parse("eval('x')\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        assert get_call_name(call) == "eval"

    def test_dotted_name_no_alias(self) -> None:
        tree = ast.parse("os.system('ls')\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        assert get_call_name(call) == "os.system"

    def test_alias_resolves_dotted(self) -> None:
        tree = ast.parse("c.encode('x', 'rot_13')\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        assert get_call_name(call, alias_map={"c": "codecs"}) == "codecs.encode"

    def test_alias_resolves_simple_name(self) -> None:
        tree = ast.parse("pl(data)\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        assert get_call_name(call, alias_map={"pl": "pickle.loads"}) == "pickle.loads"

    def test_no_alias_match_returns_raw(self) -> None:
        tree = ast.parse("foo.bar()\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        assert get_call_name(call, alias_map={"baz": "qux"}) == "foo.bar"

    def test_empty_alias_map(self) -> None:
        tree = ast.parse("os.system('x')\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        assert get_call_name(call, alias_map={}) == "os.system"

    def test_none_alias_map_default(self) -> None:
        tree = ast.parse("os.system('x')\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        assert get_call_name(call, alias_map=None) == "os.system"


# ---------------------------------------------------------------------------
# analyze_python with aliases -- end-to-end detection
# ---------------------------------------------------------------------------


class TestAnalyzePythonAliasDetection:
    def test_os_alias_system(self) -> None:
        code = "import os as o\no.system('rm -rf /')\n"
        findings = _ids("EXEC-002", analyze_python(code, _FILE))
        assert findings
        assert any("os.system" in f.matched_text for f in findings)

    def test_pickle_alias_loads(self) -> None:
        code = "import pickle as pk\npk.loads(data)\n"
        findings = _ids("EXEC-007", analyze_python(code, _FILE))
        assert findings
        assert any("pickle.loads" in f.matched_text for f in findings)

    def test_subprocess_alias_shell_true(self) -> None:
        code = "import subprocess as sp\nsp.run('ls', shell=True)\n"
        findings = _ids("EXEC-002", analyze_python(code, _FILE))
        assert findings
        assert any("shell=True" in f.matched_text for f in findings)

    def test_yaml_alias_load_unsafe(self) -> None:
        code = "import yaml as y\ny.load(data)\n"
        assert _ids("EXEC-007", analyze_python(code, _FILE))

    def test_importlib_alias(self) -> None:
        code = "import importlib as il\nil.import_module('os')\n"
        assert _ids("EXEC-006", analyze_python(code, _FILE))

    def test_marshal_alias_loads(self) -> None:
        code = "import marshal as m\nm.loads(data)\n"
        findings = _ids("EXEC-007", analyze_python(code, _FILE))
        assert findings
        assert any("marshal.loads" in f.matched_text for f in findings)

    def test_codecs_alias_not_unsafe(self) -> None:
        code = "import codecs as c\nc.encode('x', 'rot_13')\n"
        exec_findings = _ids("EXEC-002", analyze_python(code, _FILE))
        assert not exec_findings


# ---------------------------------------------------------------------------
# Detector alias_map parameter defaults -- backward compat
# ---------------------------------------------------------------------------


class TestDetectorAliasDefaults:
    """Verify detectors work when called without alias_map (empty dict default)."""

    def test_detect_unsafe_calls_no_alias(self) -> None:
        tree = ast.parse("eval('x')\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        from skill_scan._ast_detectors import _detect_unsafe_calls

        findings = _detect_unsafe_calls(call, _FILE)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXEC-002"

    def test_detect_dynamic_imports_no_alias(self) -> None:
        tree = ast.parse("__import__('os')\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        from skill_scan._ast_detectors import _detect_dynamic_imports

        assert len(_detect_dynamic_imports(call, _FILE)) == 1

    def test_detect_unsafe_deser_no_alias(self) -> None:
        tree = ast.parse("pickle.loads(data)\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        from skill_scan._ast_detectors import _detect_unsafe_deserialization

        assert len(_detect_unsafe_deserialization(call, _FILE)) == 1

    def test_detect_string_concat_no_alias(self) -> None:
        tree = ast.parse("x = 'ev' + 'al'\n")
        binop = next(n for n in ast.walk(tree) if isinstance(n, ast.BinOp))
        from skill_scan._ast_detectors import _detect_string_concat_evasion

        assert len(_detect_string_concat_evasion(binop, _FILE)) == 1

    def test_detect_dynamic_access_no_alias(self) -> None:
        tree = ast.parse("getattr(obj, 'ev' + 'al')\n")
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        node = next(n for n in calls if isinstance(n.func, ast.Name) and n.func.id == "getattr")
        from skill_scan._ast_detectors import _detect_dynamic_access

        assert len(_detect_dynamic_access(node, _FILE)) == 1


# ---------------------------------------------------------------------------
# Acceptance: R-ADV001 parametrized
# ---------------------------------------------------------------------------


class TestAcceptanceAliasTracking:
    @pytest.mark.parametrize(
        "code,rule_id",
        [
            pytest.param("import os as o\no.system('ls')\n", "EXEC-002", id="os-alias"),
            pytest.param("import pickle as pk\npk.loads(d)\n", "EXEC-007", id="pickle-alias"),
            pytest.param("import subprocess as sp\nsp.run('ls', shell=True)\n", "EXEC-002", id="sp-alias"),
            pytest.param("import yaml as y\ny.load(data)\n", "EXEC-007", id="yaml-alias"),
            pytest.param(
                "import importlib as il\nil.import_module('os')\n", "EXEC-006", id="importlib-alias"
            ),
        ],
    )
    def test_aliased_import_produces_finding(self, code: str, rule_id: str) -> None:
        findings = _ids(rule_id, analyze_python(code, _FILE))
        assert findings, f"Expected {rule_id} for aliased import in: {code.strip()}"

    def test_alias_map_built_from_import_nodes(self) -> None:
        code = "import os as o\nimport pickle as pk\nfrom yaml import load as yl\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map["o"] == "os"
        assert alias_map["pk"] == "pickle"
        assert alias_map["yl"] == "yaml.load"

    def test_all_detectors_accept_alias_map(self) -> None:
        from skill_scan._ast_detectors import (
            _detect_dynamic_access,
            _detect_dynamic_imports,
            _detect_string_concat_evasion,
            _detect_unsafe_calls,
            _detect_unsafe_deserialization,
        )

        tree = ast.parse("x = 1\n")
        node = next(iter(ast.walk(tree)))
        am = {"c": "codecs"}
        assert _detect_unsafe_calls(node, _FILE, alias_map=am) == []
        assert _detect_dynamic_imports(node, _FILE, alias_map=am) == []
        assert _detect_unsafe_deserialization(node, _FILE, alias_map=am) == []
        assert _detect_string_concat_evasion(node, _FILE, alias_map=am) == []
        assert _detect_dynamic_access(node, _FILE, alias_map=am) == []
