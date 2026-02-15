"""Core scan orchestration — the I/O boundary.

Ties together config, fetching, parsing, rule loading, and matching
into a single scan() entry point that returns a ScanResult.
"""

from __future__ import annotations

import time
from pathlib import Path

from skill_scan._fetchers import LocalFetcher, SkillFetcher
from skill_scan.config import ScanConfig, load_config
from skill_scan.models import Finding, Rule, ScanResult, Verdict
from skill_scan.parser import SkillParseError, parse_skill_frontmatter
from skill_scan.rules import load_default_rules, match_line
from skill_scan.verdict import calculate_verdict, count_by_severity


def scan(
    path: str | Path,
    config: ScanConfig | None = None,
    fetcher: SkillFetcher | None = None,
) -> ScanResult:
    """Scan a skill directory and return aggregated results.

    Pipeline:
        1. Resolve path via fetcher (defaults to LocalFetcher)
        2. Load config (defaults if None)
        3. Validate SKILL.md frontmatter (R0 check)
        4. Collect text files by extension
        5. Load detection rules
        6. Scan each file line by line
        7. Assemble and return ScanResult

    Args:
        path: Path to the skill directory (string or Path object).
        config: Optional scan configuration. Uses defaults if None.
        fetcher: Optional SkillFetcher implementation. Uses LocalFetcher if None.

    Returns:
        ScanResult with findings, counts, verdict, and duration.
    """
    start = time.monotonic()

    resolved_fetcher = fetcher or LocalFetcher()
    skill_dir = resolved_fetcher.fetch(str(path))
    cfg = config if config is not None else load_config()

    if not cfg.skip_schema_validation:
        try:
            parse_skill_frontmatter(skill_dir)
        except SkillParseError as e:
            duration = time.monotonic() - start
            return ScanResult(
                findings=(),
                counts={},
                verdict=Verdict.INVALID,
                duration=duration,
                error_message=str(e),
            )

    files = _collect_files(skill_dir, cfg)
    rules = load_default_rules()
    findings = _scan_all_files(files, skill_dir, rules)

    findings_tuple = tuple(findings)
    duration = time.monotonic() - start

    return ScanResult(
        findings=findings_tuple,
        counts=count_by_severity(findings_tuple),
        verdict=calculate_verdict(findings_tuple),
        duration=duration,
    )


def _collect_files(skill_dir: Path, config: ScanConfig) -> list[Path]:
    """Walk the skill directory and collect scannable files.

    Filters files by extension (from config) and skips symlinks,
    files outside the skill directory boundary, and files exceeding
    the max_file_size threshold.

    Args:
        skill_dir: Root directory of the skill.
        config: Scan configuration with extension and size limits.

    Returns:
        Sorted list of file paths to scan.
    """
    collected: list[Path] = []
    resolved_root = skill_dir.resolve()

    for file_path in sorted(skill_dir.rglob("*")):
        if file_path.is_symlink():
            continue
        if not file_path.is_file():
            continue
        if not file_path.resolve().is_relative_to(resolved_root):
            continue
        if file_path.suffix not in config.extensions:
            continue
        try:
            if file_path.stat().st_size > config.max_file_size:
                continue
        except OSError:
            continue
        collected.append(file_path)

    return collected


def _scan_all_files(
    files: list[Path],
    skill_dir: Path,
    rules: list[Rule],
) -> list[Finding]:
    """Scan all collected files and aggregate findings.

    Args:
        files: List of file paths to scan.
        skill_dir: Root directory for computing relative paths.
        rules: Compiled detection rules.

    Returns:
        List of all findings across all files.
    """
    all_findings: list[Finding] = []
    for file_path in files:
        all_findings.extend(_scan_file(file_path, skill_dir, rules))
    return all_findings


def _scan_file(file_path: Path, skill_dir: Path, rules: list[Rule]) -> list[Finding]:
    """Scan a single file line by line against all rules.

    Reads the file as UTF-8, splits into lines, and applies match_line
    to each line with 1-based line numbering. Uses the path relative
    to the skill directory in findings.

    On UnicodeDecodeError, the file is skipped and an empty list is returned.

    Args:
        file_path: Absolute path to the file.
        skill_dir: Root directory for computing relative paths.
        rules: Compiled detection rules.

    Returns:
        List of findings from this file.
    """
    try:
        content = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    relative_path = str(file_path.relative_to(skill_dir))
    lines = content.split("\n")
    findings: list[Finding] = []

    for line_num, line in enumerate(lines, start=1):
        findings.extend(match_line(line, line_num, relative_path, rules))

    return findings
