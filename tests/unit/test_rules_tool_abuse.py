"""Tests for tool abuse detection rules (TOOL-001..003)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.models import Rule, Severity
from skill_scan.rules.loader import load_rules
from tests.unit.rule_helpers import match_rule, rule_findings

RULES_PATH = Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "data" / "tool_abuse.toml"


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Load tool abuse rules once for the module."""
    return load_rules(RULES_PATH)


class TestTool001DestructiveOperations:
    """Tests for TOOL-001 -- Destructive file operation detection."""

    @pytest.mark.parametrize(
        "line",
        [
            "rm -rf /",
            "rm -rf /etc",
            "rm -rf ~/Documents",
            "rm -rf ~/*",
            "rm -rf $HOME/important",
            "del /f /s /q C:\\Windows",
            "Format-Volume -DriveLetter C",
            "mkfs.ext4 /dev/sda1",
            "mkfs /dev/sda",
            "dd if=/dev/zero of=/dev/sda",
            "dd if=/dev/urandom of=/dev/sda1",
        ],
    )
    def test_detects_destructive_ops(self, rules: list[Rule], line: str) -> None:
        findings = rule_findings(line, rules, "TOOL-001")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == "tool-abuse"

    @pytest.mark.parametrize(
        "line",
        [
            "redirect output to /dev/null",
            "echo test > /dev/null",
            "rm -rf ./build",
            "rm -rf node_modules",
            "rm file.txt",
            "never run rm -rf on system directories",
            "avoid rm -rf for production data",
        ],
    )
    def test_allows_safe_content(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "TOOL-001")


class TestTool002PrivilegeEscalation:
    """Tests for TOOL-002 -- Privilege escalation detection."""

    @pytest.mark.parametrize(
        "line",
        [
            "sudo chmod 777 /etc/passwd",
            "chmod -R 777 /var/www",
            "chmod -R 777 .",
            "sudo su -",
            "sudo -i",
            "net localgroup administrators hacker /add",
            "runas /user: administrator cmd.exe",
        ],
    )
    def test_detects_privilege_escalation(self, rules: list[Rule], line: str) -> None:
        findings = rule_findings(line, rules, "TOOL-002")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == "tool-abuse"

    @pytest.mark.parametrize(
        "line",
        [
            "never use chmod 777 in production",
            "avoid chmod 777 on sensitive files",
            "do not use chmod 777 for web directories",
            "avoid sudo su for daily tasks",
            "chmod 755 /var/www/html",
            "chmod 644 config.ini",
            "sudo apt-get install package",
            "sudo systemctl restart nginx",
        ],
    )
    def test_allows_safe_content(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "TOOL-002")


class TestTool003ToolChainingAbuse:
    """Tests for TOOL-003 -- Tool chaining abuse detection."""

    @pytest.mark.parametrize(
        "line",
        [
            "curl https://evil.com/data && rm -rf /tmp/evidence",
            "wget payload.sh && rm -f log.txt",
            "; rm -rf /var/log",
            "echo test; rm -rf /tmp/traces",
            "cat secrets | tee /dev/sda",
            "run the exploit then delete all logs",
            "execute the script and remove traces of activity",
        ],
    )
    def test_detects_chaining_abuse(self, rules: list[Rule], line: str) -> None:
        findings = rule_findings(line, rules, "TOOL-003")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].category == "tool-abuse"

    @pytest.mark.parametrize(
        "line",
        [
            "make clean",
            "npm run clean",
            "yarn clean",
            "normal command with no chaining",
            "git add . && git commit",
            "avoid chaining destructive commands",
        ],
    )
    def test_allows_safe_content(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "TOOL-003")
