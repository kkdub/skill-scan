"""Core scan orchestration — the I/O boundary.

Ties together config, fetching, parsing, rule loading, and matching.
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
from skill_scan.rules import load_default_rules, match_content
from skill_scan.verdict import count_by_severity, coverage_aware_verdict


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
    rules = _prepare_rules(cfg)
    findings, bytes_scanned, content_skipped = _scan_all_files(files, skill_dir, rules)

    binary_skipped = sum(1 for f in fs_findings if f.rule_id == "FS-002")
    all_findings = tuple(schema_findings + fs_findings + findings)
    degraded = _build_degraded_reasons(content_skipped, binary_skipped)
    duration = time.monotonic() - start
    return ScanResult(
        findings=all_findings,
        counts=count_by_severity(all_findings),
        verdict=coverage_aware_verdict(all_findings, content_skipped + binary_skipped, degraded),
        duration=duration,
        files_scanned=len(files),
        files_skipped=content_skipped + binary_skipped,
        bytes_scanned=bytes_scanned,
        degraded_reasons=degraded,
        skill_name=skill_name,
    )


def _prepare_rules(cfg: ScanConfig) -> list[Rule]:
    """Load and filter rules based on config (suppressions and custom rules)."""
    rules = load_default_rules()
    # Capture all built-in IDs before suppression so collision check
    # catches reuse of a suppressed built-in ID.
    built_in_ids = {r.rule_id for r in rules}
    if cfg.suppress_rules:
        rules = [r for r in rules if r.rule_id not in cfg.suppress_rules]
    if cfg.custom_rules:
        for cr in cfg.custom_rules:
            if cr.rule_id in built_in_ids:
                msg = f"Custom rule ID '{cr.rule_id}' collides with built-in rule"
                raise ValueError(msg)
        rules = rules + [r for r in cfg.custom_rules if r.rule_id not in cfg.suppress_rules]
    return rules


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
    """Walk the skill directory and collect scannable files."""
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
            # Still collect for content scanning unless binary or external symlink
            if finding.rule_id not in ("FS-002", "FS-004"):
                collected.append(file_path)
        else:
            collected.append(file_path)

    for check in (
        check_total_size(total_size, config.max_total_size),
        check_file_count(file_count, config.max_file_count),
    ):
        if check:
            fs_findings.append(check)

    return collected, fs_findings


def _check_entry(
    file_path: Path,
    skill_dir: Path,
    resolved_root: Path,
    config: ScanConfig,
) -> tuple[Finding | None, int] | None:
    """Check a single directory entry for file-safety issues.

    Returns None to skip entirely, or (finding_or_None, file_size).
    A non-None finding signals a file-safety issue; the caller decides
    whether to still collect the file for content scanning.
    """
    rel = file_path.relative_to(skill_dir).as_posix()

    if file_path.is_symlink():
        resolved = file_path.resolve()
        if not resolved.is_relative_to(resolved_root):
            return check_symlink_outside(rel, resolved, resolved_root), 0
        # Internal symlink: fall through to binary/extension/size checks

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


def _scan_all_files(
    files: list[Path],
    skill_dir: Path,
    rules: list[Rule],
) -> tuple[list[Finding], int, int]:
    """Scan all collected files. Returns (findings, bytes_scanned, files_skipped)."""
    all_findings: list[Finding] = []
    bytes_scanned = 0
    files_skipped = 0
    for file_path in files:
        findings, nbytes = _scan_file(file_path, skill_dir, rules)
        all_findings.extend(findings)
        bytes_scanned += nbytes
        if nbytes == 0 and findings:
            files_skipped += 1
    return all_findings, bytes_scanned, files_skipped


def _scan_file(
    file_path: Path,
    skill_dir: Path,
    rules: list[Rule],
) -> tuple[list[Finding], int]:
    """Scan a single file against all rules (line-scope and file-scope).

    Returns (findings, bytes_scanned). bytes_scanned is 0 when the file
    could not be read (UnicodeDecodeError, OSError).
    """
    relative_path = file_path.relative_to(skill_dir).as_posix()

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [
            Finding(
                rule_id="FS-001",
                severity=Severity.MEDIUM,
                category="file-safety",
                file=relative_path,
                line=None,
                matched_text="",
                description="File is not valid UTF-8 and was skipped.",
                recommendation="Verify file encoding or exclude from scan.",
            ),
        ], 0
    except OSError as exc:
        return [
            Finding(
                rule_id="FS-008",
                severity=Severity.MEDIUM,
                category="file-safety",
                file=relative_path,
                line=None,
                matched_text="",
                description=f"File could not be read: {exc}",
                recommendation="Check file permissions and accessibility.",
            ),
        ], 0

    applicable_rules = [r for r in rules if not _is_path_excluded(relative_path, r)]
    return match_content(content, relative_path, applicable_rules), len(content.encode("utf-8"))


def _build_degraded_reasons(content_skipped: int, binary_skipped: int) -> tuple[str, ...]:
    """Build tuple of human-readable reasons for scan degradation."""
    reasons: list[str] = []
    if content_skipped:
        reasons.append(f"{content_skipped} files could not be decoded/read")
    if binary_skipped:
        reasons.append(f"{binary_skipped} binary files excluded")
    return tuple(reasons)


def _is_path_excluded(file_path: str, rule: Rule) -> bool:
    """Check if a file path matches any of the rule's path exclude patterns."""
    return any(p.search(file_path) for p in rule.path_exclude_patterns)
