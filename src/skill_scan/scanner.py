"""Core scan orchestration — the I/O boundary.

Ties together config, fetching, parsing, rule loading, and matching
into a single scan() entry point that returns a ScanResult.
"""

from __future__ import annotations

import time
from pathlib import Path

from skill_scan._fetchers import LocalFetcher, SkillFetcher
from skill_scan.config import ScanConfig, load_config
from skill_scan.file_checks import (
    check_binary,
    check_file_count,
    check_file_size,
    check_symlink_outside,
    check_total_size,
    check_unknown_extension,
)
from skill_scan.models import Finding, Rule, ScanResult, Severity
from skill_scan.parser import SkillParseError, parse_skill_frontmatter
from skill_scan.rules import load_default_rules, match_line
from skill_scan.verdict import calculate_verdict, count_by_severity


def scan(
    path: str | Path,
    config: ScanConfig | None = None,
    fetcher: SkillFetcher | None = None,
) -> ScanResult:
    """Scan a skill directory and return aggregated results."""
    start = time.monotonic()

    resolved_fetcher = fetcher or LocalFetcher()
    skill_dir = resolved_fetcher.fetch(str(path))
    cfg = config if config is not None else load_config()

    schema_findings, skill_name = _validate_schema(skill_dir, cfg)
    files, fs_findings = _collect_files(skill_dir, cfg)
    rules = load_default_rules()
    findings = _scan_all_files(files, skill_dir, rules)
    all_findings = tuple(schema_findings + fs_findings + findings)
    duration = time.monotonic() - start

    return ScanResult(
        findings=all_findings,
        counts=count_by_severity(all_findings),
        verdict=calculate_verdict(all_findings),
        duration=duration,
        files_scanned=len(files),
        skill_name=skill_name,
    )


def _validate_schema(skill_dir: Path, cfg: ScanConfig) -> tuple[list[Finding], str | None]:
    """Parse SKILL.md frontmatter and return (findings, skill_name)."""
    try:
        fields = parse_skill_frontmatter(skill_dir)
        return [], fields.get("name")
    except SkillParseError as e:
        severity = Severity.MEDIUM if cfg.strict_schema else Severity.INFO
        finding = Finding(
            rule_id="SV-001",
            severity=severity,
            category="schema-validation",
            file="SKILL.md",
            line=None,
            matched_text="",
            description=f"Schema validation failed: {e}",
            recommendation="Fix frontmatter in SKILL.md or use 'skill-scan validate' for details",
        )
        return [finding], skill_dir.name


def _collect_files(skill_dir: Path, config: ScanConfig) -> tuple[list[Path], list[Finding]]:
    """Walk the skill directory and collect scannable files.

    Returns tuple of (files to scan, file-safety findings).
    """
    collected: list[Path] = []
    fs_findings: list[Finding] = []
    resolved_root = skill_dir.resolve()
    total_size = 0

    file_count = 0
    for file_path in sorted(skill_dir.rglob("*")):
        result = _check_entry(file_path, skill_dir, resolved_root, config)
        if result is None:
            continue
        finding, size = result
        total_size += size
        file_count += 1
        if finding:
            fs_findings.append(finding)
        else:
            collected.append(file_path)

    _append_if(fs_findings, check_total_size(total_size, config.max_total_size))
    _append_if(fs_findings, check_file_count(file_count, config.max_file_count))

    return collected, fs_findings


def _check_entry(
    file_path: Path,
    skill_dir: Path,
    resolved_root: Path,
    config: ScanConfig,
) -> tuple[Finding | None, int] | None:
    """Check a single directory entry for file-safety issues.

    Returns None to skip entirely, or (finding_or_None, file_size).
    A non-None finding means the file should not be content-scanned.
    """
    rel = file_path.relative_to(skill_dir).as_posix()

    if file_path.is_symlink():
        return check_symlink_outside(rel, file_path.resolve(), resolved_root), 0

    if not file_path.is_file() or not file_path.resolve().is_relative_to(resolved_root):
        return None

    try:
        size = file_path.stat().st_size
    except OSError:
        return None

    suffix = file_path.suffix
    binary = check_binary(rel, suffix)
    if binary:
        return binary, size

    unknown = check_unknown_extension(rel, suffix, config.extensions)
    if unknown:
        return unknown, size

    size_finding = check_file_size(rel, size, config.max_file_size)
    if size_finding:
        return size_finding, size

    return None, size


def _append_if(findings: list[Finding], finding: Finding | None) -> None:
    """Append a finding to the list if it is not None."""
    if finding:
        findings.append(finding)


def _scan_all_files(
    files: list[Path],
    skill_dir: Path,
    rules: list[Rule],
) -> list[Finding]:
    """Scan all collected files and aggregate findings."""
    all_findings: list[Finding] = []
    for file_path in files:
        all_findings.extend(_scan_file(file_path, skill_dir, rules))
    return all_findings


def _scan_file(file_path: Path, skill_dir: Path, rules: list[Rule]) -> list[Finding]:
    """Scan a single file line by line against all rules.

    On UnicodeDecodeError, emits an info-level FS-001 finding.
    On OSError, the file is silently skipped.
    """
    relative_path = file_path.relative_to(skill_dir).as_posix()

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [
            Finding(
                rule_id="FS-001",
                severity=Severity.INFO,
                category="file-safety",
                file=relative_path,
                line=None,
                matched_text="",
                description="File is not valid UTF-8 and was skipped.",
                recommendation="Verify file encoding or exclude from scan.",
            ),
        ]
    except OSError:
        return []

    applicable_rules = [r for r in rules if not _is_path_excluded(relative_path, r)]

    lines = content.split("\n")
    findings: list[Finding] = []

    for line_num, line in enumerate(lines, start=1):
        findings.extend(match_line(line, line_num, relative_path, applicable_rules))

    return findings


def _is_path_excluded(file_path: str, rule: Rule) -> bool:
    """Check if a file path matches any of the rule's path exclude patterns."""
    return any(p.search(file_path) for p in rule.path_exclude_patterns)
