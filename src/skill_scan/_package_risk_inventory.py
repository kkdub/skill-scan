"""Package input collection for package-level risk analysis."""

from __future__ import annotations

from pathlib import Path

from skill_scan._package_risk_policy import ROLE_WEIGHT
from skill_scan._package_text import TextSignal, analyze_text_content, classify_file_role


def build_role_map(skill_dir: Path, files: list[Path]) -> dict[str, str]:
    """Return package-relative file roles for every scanned file."""
    result: dict[str, str] = {}
    for path in files:
        relative = path.relative_to(skill_dir).as_posix()
        result[relative] = classify_file_role(relative)
    return result


def count_roles(role_map: dict[str, str]) -> dict[str, int]:
    """Count scanned files per role."""
    counts = {role: 0 for role in ROLE_WEIGHT}
    for role in role_map.values():
        counts[role] += 1
    return {role: count for role, count in counts.items() if count > 0}


def analyze_text_files(skill_dir: Path, files: list[Path]) -> tuple[TextSignal, ...]:
    """Read text-like files and return package-level text signals."""
    signals: list[TextSignal] = []
    for path in files:
        relative = path.relative_to(skill_dir).as_posix()
        role = classify_file_role(relative)
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        signals.extend(analyze_text_content(relative, role, content))
    return tuple(signals)
