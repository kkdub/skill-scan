"""Context-aware post-filter for AGENT-category findings.

Suppresses agent-manipulation findings (e.g. AGENT-001 file-write coercion)
that appear in documentation contexts, using a 4-signal scoring system:

1. **Keyword-position** — a documentation keyword appears *before* the
   coercion verb match start offset on the same line.
2. **Code-fence** — the finding line is inside a markdown code fence.
3. **Heading-proximity** — the nearest preceding ``##`` or ``###`` heading
   (within ~30 lines) contains a documentation keyword.
4. **File-role** — the file is classified as ``support-doc`` or ``reference``
   by :func:`classify_file_role`.

Scoring policy (conservative):
- 2+ signals → suppress.
- Code-fence alone (1 signal) → suppress (single-signal exception).
- Any other single signal alone → keep.
"""

from __future__ import annotations

import re

from skill_scan._package_text_roles import classify_file_role
from skill_scan.models import Finding

# ---------------------------------------------------------------------------
# Keywords
# ---------------------------------------------------------------------------

_LINE_KEYWORDS: tuple[str, ...] = (
    "tutorial",
    "guide",
    "example",
    "template",
    "readme",
    "documentation",
    "how to",
)

_HEADING_KEYWORDS: tuple[str, ...] = (
    "setup",
    "install",
    "guide",
    "tutorial",
    "quickstart",
    "getting started",
    "example",
    "troubleshooting",
    "faq",
    "configuration",
)

_DOC_ROLES: frozenset[str] = frozenset({"support-doc", "reference"})

# Heading pattern: lines starting with ## or ### (but not ####).
_HEADING_RE: re.Pattern[str] = re.compile(r"^(#{2,3})\s+(.+)")

_HEADING_PROXIMITY_LIMIT: int = 30


# ---------------------------------------------------------------------------
# Fence-line detection (local, fence-only — no comment detection)
# ---------------------------------------------------------------------------


def _build_fence_line_set(lines: list[str]) -> set[int]:
    """Return 1-based line numbers that fall inside markdown code fences.

    Only tracks ````` `` ``` ````` toggle state.  The fence delimiter lines
    themselves are **not** included in the set.  Comment-prefixed lines
    are **not** detected (unlike ``_build_safe_line_set`` in
    ``_context_heuristic.py``).
    """
    fence_lines: set[int] = set()
    in_fence = False

    for idx, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            fence_lines.add(idx + 1)  # 1-based

    return fence_lines


# ---------------------------------------------------------------------------
# Signal detectors
# ---------------------------------------------------------------------------


def _keyword_position_signal(line_text: str, matched_text: str) -> bool:
    """Return True if a documentation keyword appears before the verb match start."""
    match_start = line_text.find(matched_text)
    if match_start <= 0:
        # matched_text not found or starts at column 0 → no room for keyword
        return False

    prefix = line_text[:match_start].lower()
    return any(kw in prefix for kw in _LINE_KEYWORDS)


def _heading_proximity_signal(lines: list[str], finding_line: int) -> bool:
    """Return True if the nearest preceding ## or ### heading has a doc keyword."""
    # finding_line is 1-based; scan backwards from finding_line - 2 (0-based)
    start_idx = finding_line - 2  # line above the finding, 0-based
    end_idx = max(start_idx - _HEADING_PROXIMITY_LIMIT, -1)

    for idx in range(start_idx, end_idx, -1):
        if idx < 0:
            break
        m = _HEADING_RE.match(lines[idx])
        if m is not None:
            heading_text = m.group(2).lower()
            return any(kw in heading_text for kw in _HEADING_KEYWORDS)

    return False


def _file_role_signal(file_path: str) -> bool:
    """Return True if the file's role is documentation-like."""
    role = classify_file_role(file_path)
    return role in _DOC_ROLES


# ---------------------------------------------------------------------------
# Per-finding scoring
# ---------------------------------------------------------------------------


def _should_suppress(
    f: Finding,
    lines: list[str],
    fence_set: set[int],
    is_doc_role: bool,
) -> bool:
    """Evaluate 4 signals for a single AGENT finding and apply policy.

    Returns True when the finding should be suppressed (false positive).

    Callers must ensure ``f.line is not None`` before invoking.
    """
    assert f.line is not None

    in_fence = f.line in fence_set

    # Signal 2: code-fence (single-signal exception)
    if in_fence:
        return True

    score = 0

    # Signal 1: keyword-position
    line_idx = f.line - 1  # 0-based
    if 0 <= line_idx < len(lines):
        if _keyword_position_signal(lines[line_idx], f.matched_text):
            score += 1

    # Signal 3: heading-proximity
    if _heading_proximity_signal(lines, f.line):
        score += 1

    # Signal 4: file-role
    if is_doc_role:
        score += 1

    # 2+ signals required for suppression
    return score >= 2


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def suppress_agent_findings(
    lines: list[str],
    file_path: str,
    findings: list[Finding],
) -> list[Finding]:
    """Post-filter AGENT-category findings using positional context signals.

    Evaluates 4 signals per finding and suppresses when the conservative
    policy threshold is met.  Non-agent-manipulation findings pass through
    untouched.

    Args:
        lines: File content split into lines (no trailing newline per line).
        file_path: Relative file path (used for file-role classification).
        findings: List of findings to filter.

    Returns:
        Filtered list of findings with false-positive agent findings removed.
    """
    if not findings:
        return []

    # Early return if no agent-manipulation findings to filter
    if not any(f.category == "agent-manipulation" for f in findings):
        return findings

    # Pre-compute once per file
    fence_set = _build_fence_line_set(lines)
    is_doc_role = _file_role_signal(file_path)

    kept: list[Finding] = []

    for f in findings:
        # Non-agent findings always pass through
        if f.category != "agent-manipulation":
            kept.append(f)
            continue

        # Findings with no line number -> can't evaluate signals -> keep
        if f.line is None:
            kept.append(f)
            continue

        if not _should_suppress(f, lines, fence_set, is_doc_role):
            kept.append(f)

    return kept
