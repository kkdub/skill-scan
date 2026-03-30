"""URL extraction and scoring for package-level risk analysis."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from skill_scan._package_text_patterns import REMOTE_SOURCE_RE as _REMOTE_SOURCE_RE
from skill_scan._package_url_patterns import (
    ENCODED_VALUE_RE as _ENCODED_VALUE_RE,
    EXECUTION_CONTEXT_RE as _EXECUTION_CONTEXT_RE,
    PASTE_MARKERS as _PASTE_MARKERS,
    RAW_HOST_MARKERS as _RAW_HOST_MARKERS,
    SHORTENER_DOMAINS as _SHORTENER_DOMAINS,
    SUSPICIOUS_EXTENSIONS as _SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_QUERY_KEY_RE as _SUSPICIOUS_QUERY_KEY_RE,
    TUNNEL_MARKERS as _TUNNEL_MARKERS,
    URL_RE as _URL_RE,
    WEBHOOK_HINT_RE as _WEBHOOK_HINT_RE,
    WEBHOOK_MARKERS as _WEBHOOK_MARKERS,
)
from skill_scan.models import Severity

_ALL_HOST_MARKERS = _WEBHOOK_MARKERS + _PASTE_MARKERS + _RAW_HOST_MARKERS + _TUNNEL_MARKERS


def extract_urls_with_context(content: str) -> list[tuple[str, str]]:
    """Extract URLs along with nearby context."""
    results: list[tuple[str, str]] = []
    for match in _URL_RE.finditer(content):
        start = max(0, match.start() - 80)
        end = min(len(content), match.end() + 80)
        results.append((match.group(0).rstrip(".,;)"), content[start:end]))
    return results


def classify_url_signal(url: str, context: str) -> tuple[str, Severity] | None:
    """Classify one URL into a package-risk driver/severity pair."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path.lower()
    query = parse_qs(parsed.query)

    if _is_suspicious_destination(host):
        driver = "exfiltration" if _looks_exfil_destination(host, path, context) else "remote-bootstrap"
        return driver, Severity.HIGH
    if _is_suspicious_payload(path, query):
        return "remote-bootstrap", Severity.MEDIUM
    if _has_execution_context(context):
        return "remote-bootstrap", Severity.MEDIUM
    return None


def has_execution_context(context: str) -> bool:
    """Return True when a URL sits in execution or remote-loading context."""
    return _has_execution_context(context)


def _has_execution_context(context: str) -> bool:
    return _EXECUTION_CONTEXT_RE.search(context) is not None or _REMOTE_SOURCE_RE.search(context) is not None


def _is_suspicious_destination(host: str) -> bool:
    if not host:
        return False
    if any(marker in host for marker in _ALL_HOST_MARKERS):
        return True
    if any(shortener == host for shortener in _SHORTENER_DOMAINS):
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _looks_exfil_destination(host: str, path: str, context: str) -> bool:
    return any(marker in host for marker in _WEBHOOK_MARKERS) or bool(
        _WEBHOOK_HINT_RE.search(path) or _WEBHOOK_HINT_RE.search(context)
    )


def _is_suspicious_payload(path: str, query: dict[str, list[str]]) -> bool:
    if any(path.endswith(ext) for ext in _SUSPICIOUS_EXTENSIONS):
        return True
    for key, values in query.items():
        if _SUSPICIOUS_QUERY_KEY_RE.search(key):
            return True
        if any(_ENCODED_VALUE_RE.search(value or "") for value in values):
            return True
    return False
