"""CLI entry point for skill-scan.

Uses click to provide the command-line interface.
This is the I/O boundary layer — it coordinates scanning and output.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import replace
from pathlib import Path

import click

from skill_scan.config import ScanConfig, load_config
from skill_scan.formatters import OutputMode, format_text
from skill_scan.json_formatter import format_json
from skill_scan.models import ScanResult, Verdict
from skill_scan.parser import SkillParseError, parse_skill_frontmatter
from skill_scan.scanner import scan

_EXIT_CODES: dict[Verdict, int] = {
    Verdict.PASS: 0,
    Verdict.FLAG: 1,
    Verdict.BLOCK: 2,
}

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _fail_on_exit_code(result: ScanResult, threshold: str) -> int:
    """Return exit code based on --fail-on threshold.

    Returns 2 if any finding is at or above the threshold severity,
    0 otherwise.
    """
    threshold_rank = _SEVERITY_RANK[threshold.lower()]
    for finding in result.findings:
        if _SEVERITY_RANK[finding.severity.value] >= threshold_rank:
            return 2
    return 0


@click.group()
def skill_scan() -> None:
    """Security scanner for agent skills."""


@skill_scan.command("scan")
@click.argument("path", type=click.Path(exists=True), required=False, default=None)
@click.option("--repo", default=None, help="GitHub repo (owner/repo or owner/repo@ref).")
@click.option("--skill-path", "skill_path", default=None, help="Subdirectory in repo (with --repo).")
@click.option("--strict-schema", is_flag=True, default=False, help="Treat schema issues as medium severity")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Output only verdict summary")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show all findings individually")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    default=None,
    help="Exit 2 if any finding at or above this severity, 0 otherwise",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Config file path.",
)
def scan_cmd(
    path: str | None,
    repo: str | None,
    skill_path: str | None,
    strict_schema: bool,
    quiet: bool,
    verbose: bool,
    fmt: str,
    fail_on: str | None,
    config_path: str | None,
) -> None:
    """Scan a skill directory for security issues."""
    _validate_scan_args(path, repo, skill_path)

    config = load_config(Path(config_path) if config_path else None)
    if strict_schema:
        config = replace(config, strict_schema=True)

    if repo:
        _scan_remote(repo, skill_path, config, fmt, quiet, verbose, fail_on)
    else:
        if path is None:  # unreachable: _validate_scan_args ensures path or repo
            raise click.UsageError("Provide either PATH or --repo.")
        _scan_local(path, config, fmt, quiet, verbose, fail_on)


def _validate_scan_args(path: str | None, repo: str | None, skill_path: str | None) -> None:
    """Validate mutually exclusive scan arguments."""
    if path and repo:
        raise click.UsageError("Cannot use both PATH and --repo. Provide one or the other.")
    if not path and not repo:
        raise click.UsageError("Provide either PATH or --repo.")
    if skill_path and not repo:
        raise click.UsageError("--skill-path requires --repo.")


def _scan_local(
    path: str,
    config: ScanConfig,
    fmt: str,
    quiet: bool,
    verbose: bool,
    fail_on: str | None,
) -> None:
    """Run scan on a local directory."""
    result = scan(path, config=config)
    _output_result(result, fmt, quiet, verbose, fail_on)


def _scan_remote(
    repo: str,
    skill_path: str | None,
    config: ScanConfig,
    fmt: str,
    quiet: bool,
    verbose: bool,
    fail_on: str | None,
) -> None:
    """Run scan on a remote GitHub repo."""
    from skill_scan._fetchers import GitHubFetcher

    fetcher = GitHubFetcher(skill_path=skill_path or "")
    try:
        result = scan(repo, config=config, fetcher=fetcher)
    finally:
        if fetcher.tmp_dir and fetcher.tmp_dir.exists():
            shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)
    _output_result(result, fmt, quiet, verbose, fail_on)


def _output_result(
    result: ScanResult,
    fmt: str,
    quiet: bool,
    verbose: bool,
    fail_on: str | None,
) -> None:
    """Format and output scan result, then exit."""
    if fmt == "json":
        output = format_json(result)
    else:
        mode = OutputMode.QUIET if quiet else OutputMode.VERBOSE if verbose else OutputMode.DEFAULT
        output = format_text(result, mode=mode)
    click.echo(output)
    exit_code = _fail_on_exit_code(result, fail_on) if fail_on is not None else _EXIT_CODES[result.verdict]
    sys.exit(exit_code)


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
