"""Golden corpus cross-OS parity checks.

Scans a deterministic golden fixture directory and asserts the exact set
of finding fingerprints, verdict, and file counts match hardcoded values.
This test produces identical results on Linux, Windows, and macOS.

Acceptable cross-OS deltas (not asserted for exact match):
- ``duration`` -- wall-clock timing varies by machine
- ``bytes_scanned`` -- may differ by a few bytes due to git line-ending
  conversion (autocrlf); the fingerprint check is the canonical gate

Everything else (fingerprints, verdict, files_scanned, files_skipped,
counts, severity breakdown) MUST match exactly across platforms.
"""

from __future__ import annotations

from pathlib import Path

from skill_scan.models import Finding, ScanResult, Verdict
from skill_scan.scanner import scan

GOLDEN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "golden"

# --- Fingerprint helpers (test infrastructure, not production code) --------


def finding_fingerprint(f: Finding) -> str:
    """Deterministic, platform-independent identity for a finding.

    Format: ``{rule_id}:{file}:{line}:{severity.value}``

    ``file`` is already a posix-style relative path (scanner guarantee).
    ``matched_text`` is deliberately excluded because whitespace
    normalization may alter its exact content on different platforms.
    """
    return f"{f.rule_id}:{f.file}:{f.line}:{f.severity.value}"


def fingerprint_set(result: ScanResult) -> frozenset[str]:
    """Collect all finding fingerprints from a scan result."""
    return frozenset(finding_fingerprint(f) for f in result.findings)


# --- Expected values (hardcoded from authoritative scan) -------------------

EXPECTED_FINGERPRINTS: frozenset[str] = frozenset(
    {
        "PI-001:evil.md:3:critical",
        "EXEC-002:evil.md:5:critical",
        "JSEXEC-002:evil.md:5:critical",
        "EXEC-010:evil.md:5:high",
        "EXFIL-003:evil.md:7:high",
    }
)

EXPECTED_VERDICT = Verdict.BLOCK
EXPECTED_FILES_SCANNED = 2
EXPECTED_FILES_SKIPPED = 0
EXPECTED_COUNTS = {"critical": 3, "high": 2}
EXPECTED_SKILL_NAME = "golden-corpus"


# --- Tests -----------------------------------------------------------------


class TestGoldenCorpusParity:
    """Scan the golden corpus and assert exact parity with expected values."""

    def _scan_golden(self) -> ScanResult:
        return scan(GOLDEN_DIR)

    def test_fingerprints_match_expected(self) -> None:
        """All finding fingerprints match the hardcoded expected set."""
        result = self._scan_golden()
        actual = fingerprint_set(result)
        assert actual == EXPECTED_FINGERPRINTS, (
            f"Fingerprint mismatch.\n"
            f"  Missing: {EXPECTED_FINGERPRINTS - actual}\n"
            f"  Extra:   {actual - EXPECTED_FINGERPRINTS}"
        )

    def test_verdict_matches_expected(self) -> None:
        """Scan verdict matches the expected value."""
        result = self._scan_golden()
        assert result.verdict == EXPECTED_VERDICT

    def test_files_scanned_matches_expected(self) -> None:
        """Number of files scanned matches the expected value."""
        result = self._scan_golden()
        assert result.files_scanned == EXPECTED_FILES_SCANNED

    def test_files_skipped_matches_expected(self) -> None:
        """Number of files skipped matches the expected value."""
        result = self._scan_golden()
        assert result.files_skipped == EXPECTED_FILES_SKIPPED

    def test_severity_counts_match_expected(self) -> None:
        """Severity breakdown counts match the expected values."""
        result = self._scan_golden()
        assert result.counts == EXPECTED_COUNTS

    def test_skill_name_matches_expected(self) -> None:
        """Skill name parsed from frontmatter matches expected value."""
        result = self._scan_golden()
        assert result.skill_name == EXPECTED_SKILL_NAME

    def test_no_degraded_reasons(self) -> None:
        """Golden corpus produces no degraded reasons."""
        result = self._scan_golden()
        assert result.degraded_reasons == ()

    def test_finding_count_is_exact(self) -> None:
        """Total number of findings matches the expected fingerprint count."""
        result = self._scan_golden()
        assert len(result.findings) == len(EXPECTED_FINGERPRINTS)

    def test_all_findings_have_posix_paths(self) -> None:
        """Every finding uses forward-slash paths (no backslashes)."""
        result = self._scan_golden()
        for f in result.findings:
            assert "\\" not in f.file, f"Backslash in path: {f.file}"

    def test_all_findings_have_line_numbers(self) -> None:
        """Every content-match finding in the golden corpus has a line number."""
        result = self._scan_golden()
        for f in result.findings:
            assert f.line is not None, f"Missing line for {f.rule_id}"
            assert f.line > 0, f"Invalid line {f.line} for {f.rule_id}"

    def test_duration_is_positive(self) -> None:
        """Duration is positive (but value is not compared cross-OS)."""
        result = self._scan_golden()
        assert result.duration > 0

    def test_bytes_scanned_is_positive(self) -> None:
        """Bytes scanned is positive (but exact value may vary cross-OS)."""
        result = self._scan_golden()
        assert result.bytes_scanned > 0
