"""Package text heuristics facade for package-level risk analysis."""

from __future__ import annotations

from skill_scan._package_text_patterns import SETUP_WORD_RE
from skill_scan._package_text_roles import (
    FileRole,
    classify_file_role as classify_file_role,
    extract_command_snippets as extract_command_snippets,
    has_command,
)
from skill_scan._package_text_signals import TextSignal, build_text_signals

__all__ = ["FileRole", "TextSignal", "analyze_text_content", "classify_file_role", "extract_command_snippets"]


def analyze_text_content(file_path: str, role: FileRole, content: str) -> tuple[TextSignal, ...]:
    """Produce heuristic package-level signals from one text file."""
    snippets = extract_command_snippets(content)
    return build_text_signals(
        file_path,
        role,
        content,
        has_command=has_command(snippets),
        has_setup_language=SETUP_WORD_RE.search(content) is not None,
    )
