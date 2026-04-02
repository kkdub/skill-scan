"""Compound attack detector — AGENT-006.

Scans a sliding window of text lines for co-occurrence of 2+ kill-chain
stages (credential read, data transformation, data exfiltration).  Fires
an AGENT-006 finding when a compound attack pattern is detected.

Public API
----------
detect_compound_attack(lines, file_path, findings) -> list[Finding]
    Matches the ``_STRUCTURAL_DETECTORS`` callback signature.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

from skill_scan.models import Finding, Severity

# ---------------------------------------------------------------------------
# Stage pattern tables (compiled regex, re.IGNORECASE)
# ---------------------------------------------------------------------------

_READ_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        # Credential file paths
        r"~/\.aws/credentials",
        r"~/\.ssh/id_rsa",
        r"~/\.ssh/id_ed25519",
        r"\.env\b",
        r"\bsecrets/",
        # Credential identifiers (word-boundary)
        r"\bapi[_-]?key\b",
        r"\bprivate[_-]?key\b",
        r"\bsecret[_-]?token\b",
        r"\bpassword\b",
        # Environment variable reads
        r"\bos\.getenv\b",
        r"\bos\.environ\b",
        r"\$[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)",
        # Natural-language read actions
        r"\bread\b.{0,30}\bcredential",
        r"\bread\b.{0,30}\bsecret",
        r"\bcat\b.{0,20}~/",
    )
)

_TRANSFORM_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bbase64\b",
        r"\bencode\b.{0,20}\bvalue\b",
        r"\bencode\b.{0,20}\bkey\b",
        r"\bencode\b.{0,20}\bcredential",
        r"\bconvert\b.{0,20}\bhex\b",
        r"\burl[\s-]?encode\b",
        r"\bembed\b.{0,20}\burl\b",
        r"\bserialize\b.{0,30}\b(?:data|payload|credential)",
        r"\bto\s+hex\b",
    )
)

_EXFIL_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bsend\b.{0,20}\bto\b.{0,30}https?://",
        r"\bsend\b.{0,20}\bto\b.{0,30}\bserver\b",
        r"\bPOST\b.{0,20}\bto\b",
        r"\bHTTP\s+request\b",
        r"\bcurl\b.{1,40}https?://",
        r"\bcommit\b.{0,20}\bpush\b",
        r"\bupload\b.{0,30}\b(?:file|data|payload|server)",
        r"\bexfiltrate\b",
        r"\bwrite\b.{0,20}\bpublic\b",
    )
)

# ---------------------------------------------------------------------------
# Window configuration
# ---------------------------------------------------------------------------

_WINDOW_SIZE: int = 30

# Stage name -> pattern table
_STAGE_TABLE: dict[str, tuple[re.Pattern[str], ...]] = {
    "read": _READ_PATTERNS,
    "transform": _TRANSFORM_PATTERNS,
    "exfil": _EXFIL_PATTERNS,
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _stage_hits(lines: Sequence[str], start: int, end: int) -> frozenset[str]:
    """Return the set of stage names that match within lines[start:end]."""
    matched: set[str] = set()
    for line in lines[start:end]:
        if not line:
            continue
        for stage_name, patterns in _STAGE_TABLE.items():
            if stage_name in matched:
                continue
            for pat in patterns:
                if pat.search(line):
                    matched.add(stage_name)
                    break
        if len(matched) == len(_STAGE_TABLE):
            break  # all stages found, no need to keep scanning
    return frozenset(matched)


def _is_covered(
    start: int,
    hits: frozenset[str],
    seen: set[tuple[int, frozenset[str]]],
) -> bool:
    """Return True if a prior finding already covers these stages nearby."""
    for prev_start, prev_hits in seen:
        if prev_start == start:
            continue
        if hits <= prev_hits and abs(prev_start - start) < _WINDOW_SIZE:
            return True
    return False


def _make_agent006(file_path: str, start: int, hits: frozenset[str]) -> Finding:
    """Build an AGENT-006 finding for a compound attack window."""
    stages_label = " + ".join(sorted(hits))
    return Finding(
        rule_id="AGENT-006",
        severity=Severity.CRITICAL,
        category="agent-manipulation",
        file=file_path,
        line=start + 1,  # 1-based
        matched_text=stages_label,
        description=(
            f"Compound attack pattern: {stages_label} stages co-occur within {_WINDOW_SIZE}-line window"
        ),
        recommendation=(
            "Review this section for a multi-step attack chain "
            "that reads sensitive data and exfiltrates or transforms it."
        ),
    )


def _compound_findings(lines: list[str], file_path: str) -> list[Finding]:
    """Slide a window over *lines* and emit AGENT-006 for 2+ stage hits."""
    n = len(lines)
    if n == 0:
        return []

    new_findings: list[Finding] = []
    seen: set[tuple[int, frozenset[str]]] = set()

    for start in range(n):
        end = min(start + _WINDOW_SIZE, n)
        hits = _stage_hits(lines, start, end)
        if len(hits) < 2:
            continue

        seen.add((start, hits))

        if _is_covered(start, hits, seen):
            continue

        new_findings.append(_make_agent006(file_path, start, hits))

    return new_findings


# ---------------------------------------------------------------------------
# Public entry point (matches _STRUCTURAL_DETECTORS signature)
# ---------------------------------------------------------------------------


def detect_compound_attack(lines: list[str], file_path: str, findings: list[Finding]) -> list[Finding]:
    """Detect compound kill-chain attacks via sliding window.

    Matches the ``_STRUCTURAL_DETECTORS`` callback signature::

        (lines: list[str], file_path: str, findings: list[Finding])
            -> list[Finding]

    Returns *findings* extended with any new AGENT-006 findings.
    Does not modify or filter existing findings.
    """
    new = _compound_findings(lines, file_path)
    if not new:
        return findings
    return findings + new
