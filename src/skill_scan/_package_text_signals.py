"""Signal building helpers for package text analysis."""

from __future__ import annotations

from dataclasses import dataclass

from skill_scan._package_text_patterns import (
    COERCION_RE,
    PIPE_TO_SHELL_RE,
    REMOTE_BOOTSTRAP_RE,
    REMOTE_SOURCE_RE,
    SECRET_REQUEST_RE,
)
from skill_scan._package_text_roles import FileRole
from skill_scan._package_text_signal_utils import deduplicate_signals, is_warning_like_reference
from skill_scan._package_url_analysis import (
    classify_url_signal,
    extract_urls_with_context,
    has_execution_context,
)
from skill_scan.models import Severity


@dataclass(slots=True, frozen=True)
class TextSignal:
    """Internal package-level heuristic signal."""

    rule_id: str
    severity: Severity
    driver: str
    file: str
    role: FileRole
    suspicious_urls: int = 0


def build_text_signals(
    file_path: str,
    role: FileRole,
    content: str,
    *,
    has_command: bool,
    has_setup_language: bool,
) -> tuple[TextSignal, ...]:
    """Build package-level signals for one text file."""
    signals: list[TextSignal] = []
    warning_like_reference = is_warning_like_reference(role, content)
    _append_operator_signals(signals, file_path, role, content, has_command, warning_like_reference)
    _append_secret_signal(signals, file_path, role, content, warning_like_reference)
    _append_remote_signals(signals, file_path, role, content, has_command, warning_like_reference)
    _append_url_signals(
        signals,
        file_path,
        role,
        content,
        has_setup_language=has_setup_language,
        warning_like_reference=warning_like_reference,
    )
    return tuple(deduplicate_signals(signals))


def _append_operator_signals(
    signals: list[TextSignal],
    file_path: str,
    role: FileRole,
    content: str,
    has_command: bool,
    warning_like_reference: bool,
) -> None:
    if warning_like_reference or not has_command:
        return
    if COERCION_RE.search(content):
        signals.append(TextSignal("PKG-001", Severity.HIGH, "operator-manipulation", file_path, role))
        return
    if role in {"entrypoint", "support-doc"} and "run" in content.lower():
        signals.append(TextSignal("PKG-001", Severity.MEDIUM, "operator-manipulation", file_path, role))


def _append_secret_signal(
    signals: list[TextSignal],
    file_path: str,
    role: FileRole,
    content: str,
    warning_like_reference: bool,
) -> None:
    if warning_like_reference:
        return
    if SECRET_REQUEST_RE.search(content):
        signals.append(TextSignal("PKG-003", Severity.HIGH, "credential-access", file_path, role))


def _append_remote_signals(
    signals: list[TextSignal],
    file_path: str,
    role: FileRole,
    content: str,
    has_command: bool,
    warning_like_reference: bool,
) -> None:
    if warning_like_reference:
        return
    if REMOTE_SOURCE_RE.search(content):
        signals.append(TextSignal("PKG-002", Severity.HIGH, "remote-bootstrap", file_path, role))
        return
    if not has_command or REMOTE_BOOTSTRAP_RE.search(content) is None:
        return
    severity = Severity.CRITICAL if PIPE_TO_SHELL_RE.search(content) else Severity.HIGH
    signals.append(TextSignal("PKG-002", severity, "remote-bootstrap", file_path, role))


def _append_url_signals(
    signals: list[TextSignal],
    file_path: str,
    role: FileRole,
    content: str,
    *,
    has_setup_language: bool,
    warning_like_reference: bool,
) -> None:
    for url, context in extract_urls_with_context(content):
        _append_single_url_signal(signals, file_path, role, url, context)
        if _needs_setup_context_signal(warning_like_reference, has_setup_language, context):
            signals.append(TextSignal("PKG-005", Severity.MEDIUM, "operator-manipulation", file_path, role))


def _append_single_url_signal(
    signals: list[TextSignal],
    file_path: str,
    role: FileRole,
    url: str,
    context: str,
) -> None:
    classified = classify_url_signal(url, context)
    if classified is None:
        return
    driver, severity = classified
    signals.append(TextSignal("PKG-004", severity, driver, file_path, role, suspicious_urls=1))


def _needs_setup_context_signal(
    warning_like_reference: bool,
    has_setup_language: bool,
    context: str,
) -> bool:
    if warning_like_reference or not has_setup_language:
        return False
    return has_execution_context(context)
