"""File content scanning — reads files and applies detection rules.

Handles file I/O (read_text), encoding errors, per-file rule filtering
via path exclusions, and delegates pattern matching to the rules engine.
"""

from __future__ import annotations

from pathlib import Path

from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding, Rule, Severity
from skill_scan.rules import match_content

_RULE_ENCODING_ERROR = "FS-001"
_RULE_FILE_SIZE = "FS-005"
_RULE_READ_ERROR = "FS-008"
_CATEGORY_FILE_SAFETY = "file-safety"


def scan_all_files(
    files: list[Path],
    skill_dir: Path,
    rules: list[Rule],
    *,
    max_file_size: int = 0,
) -> tuple[list[Finding], int, int]:
    """Scan all collected files. Returns (findings, bytes_scanned, files_skipped)."""
    all_findings: list[Finding] = []
    bytes_scanned = 0
    files_skipped = 0
    for file_path in files:
        findings, nbytes = _scan_file(file_path, skill_dir, rules, max_file_size)
        all_findings.extend(findings)
        bytes_scanned += nbytes
        if nbytes == 0 and findings:
            files_skipped += 1
    return all_findings, bytes_scanned, files_skipped


def _scan_file(
    file_path: Path,
    skill_dir: Path,
    rules: list[Rule],
    max_file_size: int,
) -> tuple[list[Finding], int]:
    """Read a file and delegate to pure decision functions.

    Returns (findings, bytes_scanned). bytes_scanned is 0 when the file
    could not be read (UnicodeDecodeError, OSError) or exceeds the size limit.
    """
    relative_path = file_path.relative_to(skill_dir).as_posix()

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [
            _read_error_finding(
                _RULE_ENCODING_ERROR,
                relative_path,
                "File is not valid UTF-8 and was skipped.",
                "Verify file encoding or exclude from scan.",
            )
        ], 0
    except OSError as exc:
        return [
            _read_error_finding(
                _RULE_READ_ERROR,
                relative_path,
                f"File could not be read: {type(exc).__name__}",
                "Check file permissions and accessibility.",
            )
        ], 0

    nbytes = len(content.encode("utf-8"))
    # Defense-in-depth: if stat() failed earlier the classifier could not
    # enforce FS-005.  Re-check the actual size after reading.
    if max_file_size and nbytes > max_file_size:
        return [
            _read_error_finding(
                _RULE_FILE_SIZE,
                relative_path,
                f"File exceeds size limit ({nbytes:,} > {max_file_size:,} bytes).",
                "Reduce file size or adjust max_file_size in config.",
            )
        ], 0

    return _apply_rules(content, relative_path, rules), nbytes


def _apply_rules(
    content: str,
    relative_path: str,
    rules: list[Rule],
) -> list[Finding]:
    """Filter rules by path exclusions, then match content. Pure — no I/O.

    For Python files, also runs AST analysis and deduplicates findings
    by (rule_id, line) so each detection appears at most once.
    """
    applicable = [r for r in rules if not _is_path_excluded(relative_path, r)]
    regex_findings = match_content(content, relative_path, applicable)
    if not relative_path.endswith(".py"):
        return regex_findings
    ast_findings = analyze_python(content, relative_path)
    active_ids = {r.rule_id for r in applicable}
    ast_findings = [f for f in ast_findings if f.rule_id in active_ids]
    return _deduplicate(regex_findings, ast_findings)


def _deduplicate(
    regex_findings: list[Finding],
    ast_findings: list[Finding],
) -> list[Finding]:
    """Merge regex and AST findings, deduplicating by (rule_id, line).

    Regex findings take priority — AST findings are only appended when
    no regex finding exists with the same (rule_id, line) pair.
    """
    seen: set[tuple[str, int | None]] = {(f.rule_id, f.line) for f in regex_findings}
    merged = list(regex_findings)
    for f in ast_findings:
        key = (f.rule_id, f.line)
        if key not in seen:
            seen.add(key)
            merged.append(f)
    return merged


def _read_error_finding(
    rule_id: str,
    relative_path: str,
    description: str,
    recommendation: str,
) -> Finding:
    """Build a Finding for a file-read failure. Pure — no I/O."""
    return Finding(
        rule_id=rule_id,
        severity=Severity.MEDIUM,
        category=_CATEGORY_FILE_SAFETY,
        file=relative_path,
        line=None,
        matched_text="",
        description=description,
        recommendation=recommendation,
    )


def _is_path_excluded(file_path: str, rule: Rule) -> bool:
    """Check if a file path matches any of the rule's path exclude patterns."""
    return any(p.search(file_path) for p in rule.path_exclude_patterns)
