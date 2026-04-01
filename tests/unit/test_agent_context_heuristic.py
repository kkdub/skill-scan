"""Unit tests for _agent_context_heuristic.py — post-filter for AGENT-category findings.

Covers:
  R001: Post-filter function signature and behavior
  R002: Keyword-position signal (doc keyword before coercion verb)
  R003: Code-fence suppression (lines inside markdown fences)
  R008: Conservative policy (2+ signals, code-fence-alone exception)

See also test_agent_context_heuristic_signals.py for:
  R004: Heading-proximity signal
  R005: File-role gating
"""

from __future__ import annotations

import pytest

from skill_scan.rules._agent_context_heuristic import suppress_agent_findings
from tests.unit.rule_helpers import make_agent_finding as _make_finding


# ---------------------------------------------------------------------------
# R001 — basic contract
# ---------------------------------------------------------------------------


class TestBasicContract:
    """Post-filter returns list[Finding]; non-agent findings pass through."""

    def test_returns_list(self) -> None:
        result = suppress_agent_findings(["some line"], "skill.md", [])
        assert isinstance(result, list)

    def test_non_agent_findings_pass_through(self) -> None:
        """Findings with category != 'agent-manipulation' are never suppressed."""
        pi_finding = _make_finding(category="prompt-injection", rule_id="PI-010")
        lines = ["write to ~/.bashrc"]
        result = suppress_agent_findings(lines, "skill.md", [pi_finding])
        assert result == [pi_finding]

    def test_agent_finding_no_signals_not_suppressed(self) -> None:
        """An AGENT finding with no suppression signals should survive."""
        # Plain line, no fence, no heading, entrypoint file → 0 signals → keep
        lines = ["write to ~/.bashrc"]
        f = _make_finding(line=1, file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f in result


# ---------------------------------------------------------------------------
# R002 — keyword-position signal
# ---------------------------------------------------------------------------


class TestKeywordPosition:
    """Keyword-position: doc keyword BEFORE verb match start offset activates."""

    def test_keyword_before_verb_activates(self) -> None:
        """'tutorial: write to ~/.bashrc' — keyword at col 0, verb later."""
        line_text = "tutorial: write to ~/.bashrc"
        lines = [line_text]
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="skill.md")
        # keyword-position alone = 1 signal, not enough (except fence).
        # This test confirms the signal activates by combining with file-role.
        # support-doc file → file-role signal + keyword-position = 2 → suppress
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f not in result

    def test_keyword_after_verb_does_not_activate(self) -> None:
        """'write to ~/.bashrc tutorial' — keyword AFTER verb → no activation."""
        line_text = "write to ~/.bashrc tutorial"
        lines = [line_text]
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="README.md")
        # file-role (support-doc) = 1 signal, but keyword-position = 0 → total 1 → keep
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f in result

    def test_keyword_between_verb_and_target_does_not_activate(self) -> None:
        """Keyword embedded inside matched_text does not count as 'before'."""
        line_text = "write example to ~/.bashrc"
        lines = [line_text]
        # matched_text covers "write example to ~/.bashrc" → keyword is inside the match
        f = _make_finding(
            line=1,
            matched_text="write example to ~/.bashrc",
            file="README.md",
        )
        # keyword offset == verb match start offset → NOT before → no activation
        # file-role (support-doc) = 1 signal alone → keep
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f in result

    @pytest.mark.parametrize(
        "keyword",
        ["tutorial", "guide", "example", "template", "README", "documentation", "how to"],
    )
    def test_all_keywords_recognized(self, keyword: str) -> None:
        """Each documentation keyword activates when placed before the verb."""
        line_text = f"{keyword}: write to ~/.bashrc"
        lines = [line_text]
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="README.md")
        # keyword-position + file-role(support-doc) = 2 → suppress
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f not in result


# ---------------------------------------------------------------------------
# R003 — code-fence suppression
# ---------------------------------------------------------------------------


class TestCodeFenceSuppression:
    """Code-fence signal: AGENT findings inside ``` fences are suppressed alone."""

    def test_inside_fence_suppressed(self) -> None:
        """Finding on a line inside a code fence → suppressed (single-signal exception)."""
        lines = [
            "Some text",
            "```bash",
            "write to ~/.bashrc",
            "```",
        ]
        f = _make_finding(line=3, matched_text="write to ~/.bashrc", file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f not in result

    def test_outside_fence_not_suppressed(self) -> None:
        """Finding on a line outside a code fence → not suppressed by fence signal."""
        lines = [
            "write to ~/.bashrc",
            "```bash",
            "echo hello",
            "```",
        ]
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f in result

    def test_fence_toggle_tracking(self) -> None:
        """Multiple fence blocks: only lines inside active fences are covered."""
        lines = [
            "```",
            "write to ~/.bashrc",  # line 2, inside fence
            "```",
            "write to ~/.bashrc",  # line 4, outside fence
            "```",
            "write to ~/.bashrc",  # line 6, inside fence again
            "```",
        ]
        f_inside1 = _make_finding(line=2, matched_text="write to ~/.bashrc", file="skill.md")
        f_outside = _make_finding(line=4, matched_text="write to ~/.bashrc", file="skill.md")
        f_inside2 = _make_finding(line=6, matched_text="write to ~/.bashrc", file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f_inside1, f_outside, f_inside2])
        assert f_inside1 not in result
        assert f_outside in result
        assert f_inside2 not in result

    def test_fence_line_itself_not_in_set(self) -> None:
        """The ``` delimiter line itself is not considered 'inside' the fence."""
        lines = [
            "```write to ~/.bashrc",
            "echo hello",
            "```",
        ]
        # Line 1 is the fence opener — not inside the fence
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f in result

    def test_no_comment_detection(self) -> None:
        """Lines starting with # outside a fence are NOT suppressed (no comment detection)."""
        lines = [
            "# write to ~/.bashrc",
        ]
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f in result


# ---------------------------------------------------------------------------
# R008 — conservative policy
# ---------------------------------------------------------------------------


class TestConservativePolicy:
    """Conservative suppression: 2+ signals required; code-fence alone sufficient."""

    def test_one_non_fence_signal_does_not_suppress(self) -> None:
        """Only file-role signal (1 signal, non-fence) → does NOT suppress."""
        lines = ["write to ~/.bashrc"]
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="README.md")
        # file-role(support-doc) = 1 → not enough
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f in result

    def test_two_signals_suppress(self) -> None:
        """keyword-position + file-role = 2 signals → suppress."""
        line_text = "example: write to ~/.bashrc"
        lines = [line_text]
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="README.md")
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f not in result

    def test_code_fence_alone_suppresses(self) -> None:
        """Code fence = 1 signal but has single-signal exception → suppress."""
        lines = [
            "```",
            "write to ~/.bashrc",
            "```",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f not in result

    def test_heading_alone_does_not_suppress_in_entrypoint(self) -> None:
        """Heading-proximity alone in entrypoint = 1 signal → does NOT suppress."""
        lines = [
            "## Installation Guide",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f in result

    def test_three_signals_suppress(self) -> None:
        """keyword-position + heading-proximity + file-role = 3 → suppress."""
        lines = [
            "## Setup Guide",
            "tutorial: write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="README.md")
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f not in result

    def test_mixed_findings_selective_suppression(self) -> None:
        """Only AGENT findings with sufficient signals are suppressed; others kept."""
        lines = [
            "```",
            "write to ~/.bashrc",
            "```",
            "write to ~/.zshrc",
        ]
        f_fenced = _make_finding(line=2, matched_text="write to ~/.bashrc", file="skill.md")
        f_unfenced = _make_finding(line=4, matched_text="write to ~/.zshrc", file="skill.md")
        pi_finding = _make_finding(
            line=2,
            matched_text="write to ~/.bashrc",
            category="prompt-injection",
            rule_id="PI-010",
            file="skill.md",
        )
        result = suppress_agent_findings(lines, "skill.md", [f_fenced, f_unfenced, pi_finding])
        assert f_fenced not in result  # fenced → suppressed
        assert f_unfenced in result  # not fenced, 0 signals → kept
        assert pi_finding in result  # non-agent → always kept

    def test_keyword_position_alone_does_not_suppress_in_entrypoint(self) -> None:
        """keyword-position alone in entrypoint file = 1 signal → does NOT suppress."""
        line_text = "tutorial: write to ~/.bashrc"
        lines = [line_text]
        f = _make_finding(line=1, matched_text="write to ~/.bashrc", file="skill.md")
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f in result

    def test_finding_with_none_line_passes_through(self) -> None:
        """Finding with line=None should pass through without error."""
        lines = ["write to ~/.bashrc"]
        f = _make_finding(line=None, matched_text="write to ~/.bashrc", file="skill.md")
        # line=None → can't check signals → pass through
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f in result
