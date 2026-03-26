"""Few-shot prompt injection detector.

Detects conversational exchange patterns (User:/Assistant:, Human:/AI:,
### User/### Assistant) used in few-shot injection attacks. Fires when
2+ complete exchange pairs are found.

Rule: PI-030 (patterns=[], detection is structural, not regex-per-line).
"""

from __future__ import annotations

import re
from collections.abc import Callable

from skill_scan.models import Finding, Rule


def _role_re(*names: str) -> re.Pattern[str]:
    """Compile a heading-or-plain-label turn pattern for the given role names.

    Heading form (``### User``, ``## Assistant``): colon optional.
    Plain label form (``User:``, ``Human:``): colon required.
    """
    alts = "|".join(names)
    return re.compile(
        rf"^(?:(?:#{{1,4}}\s+)(?:{alts})\s*:?|(?:{alts})\s*:)",
        re.IGNORECASE | re.MULTILINE,
    )


# Question turn (user/human role); colon required for plain labels, optional for headings
_QUESTION_RE = _role_re("User", "Human")
# Answer turn (assistant/AI role)
_ANSWER_RE = _role_re("Assistant", "AI")

_RULE_ID = "PI-030"
_THRESHOLD = 2  # minimum complete exchange pairs to fire


def _fewshot_pi_findings(
    lines: list[str],
    file_path: str,
    pi_rules: list[Rule],
    existing: list[Finding],
    make_finding: Callable[[Rule, str, int, re.Match[str]], Finding],
    is_excluded: Callable[[str, Rule], bool],
) -> list[Finding]:
    """Scan for few-shot conversational exchange patterns.

    Counts User/Assistant (and variant) pairs. Fires a single PI-030
    finding when 2+ complete exchange pairs are detected.

    Args:
        lines: Content split into lines.
        file_path: Path to the file being scanned.
        pi_rules: Prompt-injection rules (we look up PI-030).
        existing: Findings already produced (for dedup).
        make_finding: Callback to create a Finding from a rule + match.
        is_excluded: Callback to check exclusion patterns.

    Returns:
        List containing at most one Finding, or empty list.
    """
    rule = next((r for r in pi_rules if r.rule_id == _RULE_ID), None)
    if rule is None:
        return []

    # Skip if PI-030 already reported
    if any(f.rule_id == _RULE_ID for f in existing):
        return []

    content = "\n".join(lines)

    # Check exclusion on full content
    if is_excluded(content, rule):
        return []

    pair_count = _count_exchange_pairs(lines)
    if pair_count < _THRESHOLD:
        return []

    # Find the first question-turn match for the Finding
    m = _QUESTION_RE.search(content)
    if m is None:
        return []  # defensive: shouldn't happen if pairs > 0

    first_line = content[: m.start()].count("\n") + 1
    return [make_finding(rule, file_path, first_line, m)]


def _count_exchange_pairs(lines: list[str]) -> int:
    """Count complete question-then-answer exchange pairs.

    Walks lines sequentially: after seeing a question turn, the next
    answer turn completes a pair. Resets to look for the next question.
    """
    pairs = 0
    waiting_for_answer = False
    for line in lines:
        if _QUESTION_RE.match(line):
            waiting_for_answer = True
        elif _ANSWER_RE.match(line) and waiting_for_answer:
            pairs += 1
            waiting_for_answer = False
    return pairs
