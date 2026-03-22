"""Utility helpers for package text signal construction."""

from __future__ import annotations

from typing import TYPE_CHECKING

from skill_scan._package_text_patterns import WARNING_CONTEXT_RE
from skill_scan._package_text_roles import FileRole

if TYPE_CHECKING:
    from skill_scan._package_text_signals import TextSignal


def is_warning_like_reference(role: FileRole, content: str) -> bool:
    """Return True for reference material framed as warnings/advice."""
    return role == "reference" and WARNING_CONTEXT_RE.search(content) is not None


def deduplicate_signals(signals: list[TextSignal]) -> list[TextSignal]:
    """Deduplicate signals by rule/file/driver triple."""
    seen: set[tuple[str, str, str]] = set()
    result: list[TextSignal] = []
    for signal in signals:
        key = (signal.rule_id, signal.file, signal.driver)
        if key in seen:
            continue
        seen.add(key)
        result.append(signal)
    return result
