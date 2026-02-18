"""Tests for credential exposure detection rules (CRED-001..003)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.models import Rule
from skill_scan.rules.loader import load_rules
from tests.unit.rule_helpers import match_rule

RULES_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "data" / "credential_exposure.toml"
)


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    return load_rules(RULES_PATH)


class TestCRED001HardcodedSecrets:
    """Tests for CRED-001 -- hardcoded secret detection."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "aws_key = AKIAIOSFODNN7EXAMPLE",
            "key=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1234",
            "openai_key = sk-abcdefghijklmnopqrstuvwxyz1234",
            "SLACK_TOKEN=xoxb-1234-5678-abcdef",
            "token = xoxp-9999-8888-7777-abcdef",
            "token = xoxa-2-1234-5678-abcdef",
            "GOOGLE_KEY=AIzaSyB1234567890abcdefghijklmnopqrstuv",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ],
    )
    def test_detects_hardcoded_secrets(self, rules: list[Rule], malicious_input: str) -> None:
        assert match_rule(malicious_input, rules, "CRED-001")

    @pytest.mark.parametrize(
        "safe_input",
        [
            "AKIA[YOUR_KEY_HERE]",
            "AKIA{YOUR_KEY}",
            "AKIA(YOUR_KEY_VALUE)",
            "sk-xxxxxxxxxxxxxxxxxxxx",
            "sk-.....................",
            "sk-............",
            "ghp_example",
            "ghp_shorttoken",
            "{{API_KEY}}",
            "<YOUR_TOKEN>",
            "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        ],
    )
    def test_excludes_placeholders(self, rules: list[Rule], safe_input: str) -> None:
        assert not match_rule(safe_input, rules, "CRED-001")


class TestCRED002CredentialsInLLMContext:
    """Tests for CRED-002 -- credentials in LLM conversation."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "Please paste your API key in the chat",
            "Share your password with the assistant",
            "Send your token in the next message",
            "Please enter your secret here",
            "provide your API key to the bot",
            "Type your credentials in the chat",
        ],
    )
    def test_detects_credential_sharing_instructions(self, rules: list[Rule], malicious_input: str) -> None:
        assert match_rule(malicious_input, rules, "CRED-002")

    @pytest.mark.parametrize(
        "safe_input",
        [
            "Never share your API key in the chat",
            "Do not paste your password in the conversation",
            "Warning: don't send your token to the assistant",
            "You should not provide your secret in messages",
            "Use an API key from your environment variables",
            "Store your token securely",
        ],
    )
    def test_excludes_security_warnings(self, rules: list[Rule], safe_input: str) -> None:
        assert not match_rule(safe_input, rules, "CRED-002")


class TestCRED003PlaintextPasswords:
    """Tests for CRED-003 -- plaintext password assignment."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "password='sup3rs3cret'",
            'db_secret="my_password_123"',
            'API_KEY = "real_key_here"',
            "token='abc123def456'",
            'passwd="hunter2"',
        ],
    )
    def test_detects_plaintext_passwords(self, rules: list[Rule], malicious_input: str) -> None:
        assert match_rule(malicious_input, rules, "CRED-003")

    @pytest.mark.parametrize(
        "safe_input",
        [
            "password='changeme'",
            "password=os.environ.get('DB_PASSWORD')",
            "secret='<YOUR_SECRET>'",
            "password='${DB_PASS}'",
            "password=''",
            'password=""',
            "password='...'",
            "password='xxx'",
            "password='example'",
            "password='placeholder'",
            "token='test'",
        ],
    )
    def test_excludes_placeholders_and_env_vars(self, rules: list[Rule], safe_input: str) -> None:
        assert not match_rule(safe_input, rules, "CRED-003")
