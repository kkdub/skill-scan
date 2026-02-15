"""CLI entry point for skill-scan.

Uses click to provide the command-line interface.
This is the I/O boundary layer — it coordinates scanning and output.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from skill_scan.config import ScanConfig
from skill_scan.formatters import OutputMode, format_text
from skill_scan.models import Verdict
from skill_scan.parser import SkillParseError, parse_skill_frontmatter
from skill_scan.scanner import scan

_EXIT_CODES: dict[Verdict, int] = {
    Verdict.PASS: 0,
    Verdict.FLAG: 1,
    Verdict.BLOCK: 2,
}


@click.group()
def skill_scan() -> None:
    """Security scanner for agent skills."""


@skill_scan.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--strict-schema", is_flag=True, default=False, help="Treat schema issues as medium severity")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Output only verdict summary")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show all findings individually")
def scan_cmd(path: str, strict_schema: bool, quiet: bool, verbose: bool) -> None:
    """Scan a skill directory for security issues."""
    config = ScanConfig(strict_schema=strict_schema)
    result = scan(path, config=config)
    mode = OutputMode.QUIET if quiet else OutputMode.VERBOSE if verbose else OutputMode.DEFAULT
    output = format_text(result, mode=mode)
    click.echo(output)
    sys.exit(_EXIT_CODES[result.verdict])


@skill_scan.command("validate")
@click.argument("path", type=click.Path(exists=True))
def validate_cmd(path: str) -> None:
    """Validate skill frontmatter schema."""
    try:
        fields = parse_skill_frontmatter(Path(path))
        click.echo(f"Valid skill: {fields.get('name', 'unknown')}")
        sys.exit(0)
    except SkillParseError as e:
        click.echo(f"Validation failed: {e}", err=True)
        sys.exit(1)
