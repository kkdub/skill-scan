"""Regexes and marker tables for package URL analysis."""

from __future__ import annotations

import re

URL_RE = re.compile(r"https?://[^\s<>()\"'`]+")
EXECUTION_CONTEXT_RE = re.compile(
    r"(?is)\b(run|execute|install|bootstrap|download|fetch|load|source|invoke|curl|wget|iwr|irm)\b"
)
REMOTE_SOURCE_RE = re.compile(
    r"(?is)(source|config[_-]?url|instruction[_-]?url|skill[_-]?url|manifest[_-]?url)\s*[:=]\s*https?://"
)
WEBHOOK_HINT_RE = re.compile(r"(?i)(webhook|callback|beacon|c2|exfil|collect)")
SUSPICIOUS_QUERY_KEY_RE = re.compile(
    r"(?i)(token|secret|key|password|cookie|callback|webhook|beacon|session)"
)
ENCODED_VALUE_RE = re.compile(r"%[0-9a-fA-F]{2}|[A-Za-z0-9+/]{24,}={0,2}")
SHORTENER_DOMAINS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl")
RAW_HOST_MARKERS = ("raw.githubusercontent.com", "gist.githubusercontent.com", "gitlab.com")
TUNNEL_MARKERS = ("ngrok", "trycloudflare", "loca.lt")
WEBHOOK_MARKERS = ("webhook.site", "discord.com", "hooks.slack.com")
PASTE_MARKERS = ("pastebin.com", "paste.rs", "paste.ee", "transfer.sh", "0x0.st")
SUSPICIOUS_EXTENSIONS = (".sh", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".pkg", ".dmg", ".zip", ".tar.gz")
