"""File content scanning — reads files and applies detection rules.

Handles file I/O (read_text), encoding errors, per-file rule filtering
via path exclusions, and delegates pattern matching to the rules engine.
"""

from __future__ import annotations

from pathlib import Path

from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules import match_content

_RULE_ENCODING_ERROR = "FS-001"
_RULE_READ_ERROR = "FS-008"
_CATEGORY_FILE_SAFETY = "file-safety"


def scan_all_files(
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
                rule_id=_RULE_ENCODING_ERROR,
                severity=Severity.MEDIUM,
                category=_CATEGORY_FILE_SAFETY,
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
                rule_id=_RULE_READ_ERROR,
                severity=Severity.MEDIUM,
                category=_CATEGORY_FILE_SAFETY,
                file=relative_path,
                line=None,
                matched_text="",
                description=f"File could not be read: {type(exc).__name__}",
                recommendation="Check file permissions and accessibility.",
            ),
        ], 0

    applicable_rules = [r for r in rules if not _is_path_excluded(relative_path, r)]
    return match_content(content, relative_path, applicable_rules), len(content.encode("utf-8"))


def _is_path_excluded(file_path: str, rule: Rule) -> bool:
    """Check if a file path matches any of the rule's path exclude patterns."""
    return any(p.search(file_path) for p in rule.path_exclude_patterns)
