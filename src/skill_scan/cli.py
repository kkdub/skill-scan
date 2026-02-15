"""CLI entry point for skill-scan.

Uses click to provide the command-line interface.
This is the I/O boundary layer — it coordinates scanning and output.
"""

from __future__ import annotations

import sys

import click

from skill_scan.formatters import format_text
from skill_scan.models import Verdict
from skill_scan.scanner import scan

_EXIT_CODES: dict[Verdict, int] = {
    Verdict.PASS: 0,
    Verdict.FLAG: 1,
    Verdict.BLOCK: 2,
    Verdict.INVALID: 3,
}


@click.group()
def skill_scan() -> None:
    """Security scanner for agent skills."""


@skill_scan.command("scan")
@click.argument("path", type=click.Path(exists=True))
def scan_cmd(path: str) -> None:
    """Scan a skill directory for security issues."""
    result = scan(path)
    output = format_text(result)
    click.echo(output)
    sys.exit(_EXIT_CODES[result.verdict])
