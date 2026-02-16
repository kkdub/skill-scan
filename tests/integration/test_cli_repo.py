"""Integration tests for --repo CLI option (remote scanning)."""

from __future__ import annotations

import builtins
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

from click.testing import CliRunner

from skill_scan.cli import skill_scan
from tests.conftest import make_skill_dir


class TestRepoOptionValidation:
    """Tests for --repo argument validation."""

    def test_repo_and_path_mutually_exclusive(self, tmp_path: Path) -> None:
        """Cannot use both PATH and --repo."""
        skill_dir = make_skill_dir(tmp_path)
        runner = CliRunner()

        result = runner.invoke(skill_scan, ["scan", str(skill_dir), "--repo", "owner/repo"])

        assert result.exit_code != 0
        assert "Cannot use both" in result.output

    def test_neither_path_nor_repo_shows_error(self) -> None:
        """Must provide either PATH or --repo."""
        runner = CliRunner()

        result = runner.invoke(skill_scan, ["scan"])

        assert result.exit_code != 0
        assert "Provide either" in result.output

    def test_skill_path_without_repo_shows_error(self, tmp_path: Path) -> None:
        """--skill-path requires --repo."""
        skill_dir = make_skill_dir(tmp_path)
        runner = CliRunner()

        result = runner.invoke(skill_scan, ["scan", str(skill_dir), "--skill-path", "sub"])

        assert result.exit_code != 0
        assert "--skill-path requires --repo" in result.output


class TestRepoMissingHttpx:
    """Tests for --repo when httpx is not installed."""

    def test_missing_httpx_shows_install_message(self) -> None:
        """--repo without httpx gives helpful install instructions."""
        original_import = builtins.__import__

        def mock_import(name: str, *args: Any, **kwargs: Any) -> object:
            if name == "httpx":
                raise ImportError("No module named 'httpx'")
            return original_import(name, *args, **kwargs)

        runner = CliRunner()
        saved = sys.modules.pop("httpx", None)
        try:
            with patch.object(builtins, "__import__", side_effect=mock_import):
                result = runner.invoke(skill_scan, ["scan", "--repo", "owner/repo"])
        finally:
            if saved is not None:
                sys.modules["httpx"] = saved

        assert result.exit_code != 0
        # Error appears in output or exception
        error_text = result.output + (str(result.exception) if result.exception else "")
        assert "pip install skill-scan[remote]" in error_text


class TestLocalScanStillWorks:
    """Ensure local scanning is unaffected by --repo changes."""

    def test_local_path_scan_returns_pass_for_clean_skill(self, tmp_path: Path) -> None:
        """Positional PATH argument still works as before."""
        skill_dir = make_skill_dir(tmp_path)
        runner = CliRunner()

        result = runner.invoke(skill_scan, ["scan", str(skill_dir)])

        assert result.exit_code == 0
        assert "No security issues found" in result.output
