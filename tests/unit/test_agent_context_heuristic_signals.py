"""Unit tests for _agent_context_heuristic.py — heading-proximity and file-role signals.

Covers:
  R004: Heading-proximity signal (## / ### with doc keyword within ~30 lines)
  R005: File-role gating (support-doc/reference vs entrypoint/script/config)
"""

from __future__ import annotations

import pytest

from skill_scan.rules._agent_context_heuristic import suppress_agent_findings
from tests.unit.rule_helpers import make_agent_finding as _make_finding


# ---------------------------------------------------------------------------
# R004 — heading-proximity signal
# ---------------------------------------------------------------------------


class TestHeadingProximity:
    """Heading-proximity: nearest preceding ## or ### with doc keyword within ~30 lines."""

    def test_doc_heading_within_range_activates(self) -> None:
        """## Installation Guide heading 5 lines above -> activates."""
        lines = [""] * 50
        lines[9] = "## Installation Guide"
        lines[14] = "write to ~/.bashrc"
        f = _make_finding(line=15, matched_text="write to ~/.bashrc", file="README.md")
        # heading-proximity + file-role(support-doc) = 2 -> suppress
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f not in result

    def test_heading_beyond_30_lines_does_not_activate(self) -> None:
        """Heading 35 lines above -> outside ~30 line window -> no activation."""
        lines = [""] * 60
        lines[0] = "## Setup Guide"
        lines[35] = "write to ~/.bashrc"
        f = _make_finding(line=36, matched_text="write to ~/.bashrc", file="README.md")
        # heading too far -> heading-proximity = 0, file-role = 1 -> total 1 -> keep
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f in result

    def test_heading_without_doc_keyword_does_not_activate(self) -> None:
        """## Security Audit heading -> no doc keyword -> no activation."""
        lines = [
            "## Security Audit",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="README.md")
        # heading-proximity = 0, file-role = 1 -> total 1 -> keep
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f in result

    def test_h1_heading_does_not_activate(self) -> None:
        """# Setup Guide (h1) -> not ## or ### -> no activation."""
        lines = [
            "# Setup Guide",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="README.md")
        # heading-proximity = 0 (h1 not checked), file-role = 1 -> keep
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f in result

    @pytest.mark.parametrize(
        "heading_keyword",
        [
            "setup",
            "install",
            "guide",
            "tutorial",
            "quickstart",
            "getting started",
            "example",
            "troubleshooting",
            "FAQ",
            "configuration",
        ],
    )
    def test_all_heading_keywords_recognized(self, heading_keyword: str) -> None:
        """Each heading doc keyword activates the heading-proximity signal."""
        lines = [
            f"## {heading_keyword.title()}",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="README.md")
        # heading-proximity + file-role = 2 -> suppress
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f not in result

    def test_nearest_heading_wins(self) -> None:
        """When two headings exist, the nearest preceding one is checked."""
        lines = [
            "## Installation Guide",
            "",
            "## Security Audit",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=4, matched_text="write to ~/.bashrc", file="README.md")
        # Nearest heading is "Security Audit" (no doc keyword) -> no activation
        # file-role = 1 -> total 1 -> keep
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f in result


# ---------------------------------------------------------------------------
# R005 — file-role gating
# ---------------------------------------------------------------------------


class TestFileRoleGating:
    """File-role signal contributes only for documentation-role files."""

    def test_support_doc_contributes(self) -> None:
        """README.md -> support-doc role -> file-role signal contributes."""
        lines = [
            "## Setup Guide",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="README.md")
        # heading-proximity(1) + file-role(1) = 2 -> suppress
        result = suppress_agent_findings(lines, "README.md", [f])
        assert f not in result

    def test_reference_contributes(self) -> None:
        """CHANGELOG.md -> reference role -> file-role signal contributes."""
        lines = [
            "## Setup Guide",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="CHANGELOG.md")
        # heading-proximity(1) + file-role(1) = 2 -> suppress
        result = suppress_agent_findings(lines, "CHANGELOG.md", [f])
        assert f not in result

    def test_entrypoint_does_not_contribute(self) -> None:
        """skill.md -> entrypoint role -> file-role signal does NOT contribute."""
        lines = [
            "## Setup Guide",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="skill.md")
        # heading-proximity(1) + file-role(0, entrypoint) = 1 -> keep
        result = suppress_agent_findings(lines, "skill.md", [f])
        assert f in result

    def test_script_does_not_contribute(self) -> None:
        """install.sh -> script role -> file-role signal does NOT contribute."""
        lines = [
            "## Setup Guide",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="install.sh")
        # heading-proximity(1) + file-role(0, script) = 1 -> keep
        result = suppress_agent_findings(lines, "install.sh", [f])
        assert f in result

    def test_config_does_not_contribute(self) -> None:
        """pyproject.toml -> config role -> file-role signal does NOT contribute."""
        lines = [
            "## Setup Guide",
            "write to ~/.bashrc",
        ]
        f = _make_finding(line=2, matched_text="write to ~/.bashrc", file="pyproject.toml")
        # heading-proximity(1) + file-role(0, config) = 1 -> keep
        result = suppress_agent_findings(lines, "pyproject.toml", [f])
        assert f in result
