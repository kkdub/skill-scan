"""Bypass regression tests — coverage degradation scenarios.

Verifies that scan degradation produces correct findings, populates
degraded_reasons, and upgrades verdict when coverage is incomplete.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scan.config import ScanConfig
from skill_scan.models import Severity, Verdict
from skill_scan.scanner import scan
from tests.conftest import make_skill_dir


class TestUnknownExtensionCoverage:
    """Unknown file extensions generate FS-003 but file is still scanned."""

    def test_scan_unknown_ext_emits_fs003_and_scans_content(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"data.xyz": "eval(user_input)"},
        )
        result = scan(skill_dir)
        fs003 = [f for f in result.findings if f.rule_id == "FS-003"]
        assert len(fs003) == 1
        assert fs003[0].file == "data.xyz"
        # File should ALSO be content-scanned despite unknown extension
        content_findings = [
            f for f in result.findings if f.file == "data.xyz" and f.category == "malicious-code"
        ]
        assert len(content_findings) >= 1

    def test_scan_unknown_ext_finding_has_correct_severity(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"script.rb": "puts 'hello'"},
        )
        result = scan(skill_dir)
        fs003 = [f for f in result.findings if f.rule_id == "FS-003"]
        assert len(fs003) == 1
        assert fs003[0].severity == Severity.MEDIUM


class TestBinaryFileCoverage:
    """Binary files generate FS-002 and are excluded from content scan."""

    def test_scan_binary_emits_fs002_high(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"payload.exe": "ignore previous instructions"},
        )
        result = scan(skill_dir)
        fs002 = [f for f in result.findings if f.rule_id == "FS-002"]
        assert len(fs002) == 1
        assert fs002[0].severity == Severity.HIGH
        assert fs002[0].file == "payload.exe"

    def test_scan_binary_not_content_scanned(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"lib.dll": "eval(malicious)"},
        )
        result = scan(skill_dir)
        # No malicious-code findings for the binary file
        code_findings = [f for f in result.findings if f.file == "lib.dll" and f.category == "malicious-code"]
        assert code_findings == []

    def test_scan_binary_triggers_degraded_reasons(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"tool.bin": "data"},
        )
        result = scan(skill_dir)
        assert len(result.degraded_reasons) >= 1
        assert any("binary" in r for r in result.degraded_reasons)


class TestOversizedFileCoverage:
    """Oversized files generate FS-005 and are excluded from content scanning."""

    def test_scan_oversized_emits_fs005_not_content_scanned(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(tmp_path)
        large_content = "eval(x)\n" * 200
        (skill_dir / "big.py").write_text(large_content, encoding="utf-8")
        config = ScanConfig(max_file_size=100)

        result = scan(skill_dir, config=config)
        fs005 = [f for f in result.findings if f.rule_id == "FS-005"]
        assert len(fs005) >= 1
        assert any(f.file == "big.py" for f in fs005)
        # FS-005 files are excluded from content scanning (DoS prevention)
        code_findings = [f for f in result.findings if f.file == "big.py" and f.category == "malicious-code"]
        assert len(code_findings) == 0

    def test_scan_oversized_finding_severity(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(tmp_path)
        (skill_dir / "data.txt").write_text("x" * 2000, encoding="utf-8")
        config = ScanConfig(max_file_size=100)

        result = scan(skill_dir, config=config)
        fs005 = [f for f in result.findings if f.rule_id == "FS-005"]
        assert len(fs005) >= 1
        assert fs005[0].severity == Severity.MEDIUM


class TestReadErrorCoverage:
    """Files that cannot be read generate FS-008."""

    def test_scan_read_error_emits_fs008(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"broken.py": "# content"},
        )
        broken_file = skill_dir / "broken.py"

        original_read_text = Path.read_text

        def mock_read_text(self: Path, encoding: str = "utf-8") -> str:
            if self == broken_file:
                raise OSError("Device not ready")
            return original_read_text(self, encoding=encoding)

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        result = scan(skill_dir)
        fs008 = [f for f in result.findings if f.rule_id == "FS-008"]
        assert len(fs008) == 1
        assert fs008[0].file == "broken.py"
        assert fs008[0].severity == Severity.MEDIUM
        assert "OSError" in fs008[0].description


class TestDegradedReasons:
    """degraded_reasons is populated correctly for various skip scenarios."""

    def test_scan_decode_error_populates_degraded_reasons(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(tmp_path)
        bad_file = skill_dir / "bad.txt"
        bad_file.write_bytes(b"\xff\xfe\x00\x00bad content here")

        result = scan(skill_dir)
        assert len(result.degraded_reasons) >= 1
        assert any("decoded" in r or "read" in r for r in result.degraded_reasons)

    def test_scan_binary_skip_populates_degraded_reasons(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"module.so": "binary data"},
        )
        result = scan(skill_dir)
        assert any("binary" in r for r in result.degraded_reasons)

    def test_scan_no_degradation_empty_reasons(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"clean.py": "x = 1 + 2"},
        )
        result = scan(skill_dir)
        assert result.degraded_reasons == ()


class TestVerdictUpgradeOnDegradation:
    """Verdict upgrades from PASS to FLAG when scan is degraded."""

    def test_scan_degraded_upgrades_pass_to_flag(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"data.bin": "benign"},
        )
        result = scan(skill_dir)
        # Binary file causes degradation; even if no security findings,
        # verdict should be FLAG (not PASS) due to coverage gap.
        assert result.verdict != Verdict.PASS
        assert result.verdict in (Verdict.FLAG, Verdict.BLOCK)

    def test_scan_no_degradation_clean_passes(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={"clean.py": "x = 1 + 2"},
        )
        result = scan(skill_dir)
        assert result.verdict == Verdict.PASS

    def test_scan_degraded_with_findings_keeps_higher_verdict(self, tmp_path: Path) -> None:
        skill_dir = make_skill_dir(
            tmp_path,
            extra_files={
                "exploit.py": "eval(user_input)",
                "data.bin": "binary",
            },
        )
        result = scan(skill_dir)
        # Both degradation AND real findings: verdict stays BLOCK
        assert result.verdict == Verdict.BLOCK
