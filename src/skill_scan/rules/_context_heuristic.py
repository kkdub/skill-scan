"""Context heuristic suppression for documentation contexts.

Suppresses PI-010+ findings that occur inside markdown code fences or
comment lines (# / //). Does NOT suppress PI-001..009 (R-IMP001 protection)
or non-PI findings. Does NOT suppress findings in Python triple-quoted
string literals -- only markdown code fences and comment markers are
considered safe contexts.
"""

from __future__ import annotations

from skill_scan.models import Finding


def _is_suppressible(rule_id: str) -> bool:
    """Return True if the rule is PI-010 or higher (eligible for suppression)."""
    if not rule_id.startswith("PI-"):
        return False
    try:
        num = int(rule_id.split("-")[1])
    except (IndexError, ValueError):
        return False
    return num >= 10


def _build_safe_line_set(lines: list[str]) -> set[int]:
    """Identify 1-based line numbers that are in a safe documentation context.

    Safe contexts:
    - Lines inside markdown code fences (``` ... ```)
    - Lines starting with # or // (comment markers), with optional leading whitespace
    """
    safe: set[int] = set()
    in_fence = False

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        # Toggle code-fence state on lines starting with ```
        if line.startswith("```"):
            in_fence = not in_fence
            continue

        line_num = idx + 1  # 1-based

        if in_fence:
            safe.add(line_num)
        elif line.startswith("#") or line.startswith("//"):
            safe.add(line_num)

    return safe


def suppress_in_safe_context(lines: list[str], findings: list[Finding]) -> list[Finding]:
    """Filter out PI-010+ findings on lines in safe documentation contexts.

    Returns a new list; the original is not mutated.
    """
    if not findings:
        return []

    safe_lines = _build_safe_line_set(lines)

    return [
        f
        for f in findings
        if not (f.line is not None and f.line in safe_lines and _is_suppressible(f.rule_id))
    ]
