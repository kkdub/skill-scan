"""Core scan orchestration for the skill-scan pipeline.

Ties together config, fetching, parsing, rule loading, and matching.
File collection is handled by file_collector, content scanning by
content_scanner. This module coordinates the high-level flow and wires them together.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from skill_scan._fetchers import LocalFetcher, SkillFetcher
from skill_scan.config import ScanConfig, load_config
from skill_scan.content_scanner import scan_all_files
from skill_scan.file_classifier import classify_entries
from skill_scan.file_collector import walk_skill_dir
from skill_scan.models import Finding, Rule, ScanResult, Severity
from skill_scan.parser import SkillParseError, parse_skill_frontmatter
from skill_scan.rules import load_default_rules
from skill_scan.verdict import count_by_severity, coverage_aware_verdict

_RULE_BINARY = "FS-002"
_RULE_SCHEMA = "SV-001"
_CATEGORY_SCHEMA = "schema-validation"


def scan(
    path: str | Path,
    config: ScanConfig | None = None,
    fetcher: SkillFetcher | None = None,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> ScanResult:
    """Scan a skill directory and return aggregated results."""
    start = clock()

    resolved_fetcher = fetcher or LocalFetcher()
    skill_dir = resolved_fetcher.fetch(str(path))
    cfg = config if config is not None else load_config()

    schema_findings, skill_name = _validate_schema(skill_dir, cfg)
    entries, resolved_root = walk_skill_dir(skill_dir)
    files, fs_findings = classify_entries(entries, resolved_root, cfg)
    rules = _prepare_rules(cfg)
    findings, bytes_scanned, content_skipped = scan_all_files(files, skill_dir, rules)

    binary_skipped = sum(1 for f in fs_findings if f.rule_id == _RULE_BINARY)
    all_findings = tuple(schema_findings + fs_findings + findings)
    degraded = _build_degraded_reasons(content_skipped, binary_skipped)
    duration = clock() - start
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
            rule_id=_RULE_SCHEMA,
            severity=severity,
            category=_CATEGORY_SCHEMA,
            file="SKILL.md",
            line=None,
            matched_text="",
            description=f"Schema validation failed: {e}",
            recommendation="Fix frontmatter in SKILL.md or use 'skill-scan validate' for details",
        )
        return [finding], skill_dir.name


def _build_degraded_reasons(content_skipped: int, binary_skipped: int) -> tuple[str, ...]:
    """Build tuple of human-readable reasons for scan degradation."""
    reasons: list[str] = []
    if content_skipped:
        reasons.append(f"{content_skipped} files could not be decoded/read")
    if binary_skipped:
        reasons.append(f"{binary_skipped} binary files excluded")
    return tuple(reasons)
