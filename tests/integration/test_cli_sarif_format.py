"""Integration tests for --format sarif CLI option."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from skill_scan.cli import skill_scan as skill_scan_cli
from tests.conftest import make_skill_dir


class TestCLISarifFormat:
    """Integration tests for --format sarif CLI option."""

    def test_cli_sarif_format_clean_skill_exits_zero(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(skill_scan_cli, ["scan", "--format", "sarif", str(skill_dir)])
        assert result.exit_code == 0
