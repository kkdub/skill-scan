"""Tests for content_scanner — file reading, error handling, and size limits."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor as _RealProcessPoolExecutor
from pathlib import Path
from unittest.mock import patch

from skill_scan.content_scanner import MIN_FILES_FOR_CONCURRENCY, scan_all_files


class TestScanAllFilesSizeLimit:
    """Defense-in-depth: content scanner enforces FS-005 after reading.

    If stat() failed in the collector, the classifier could not enforce
    the file-size limit. The content scanner re-checks actual content
    size to close this gap.
    """

    def test_oversized_file_emits_fs005_finding(self, tmp_path: Path) -> None:
        """A file larger than max_file_size is rejected with FS-005."""
        big = tmp_path / "big.py"
        big.write_text("x" * 200, encoding="utf-8")

        findings, scanned, skipped, _ = scan_all_files([big], tmp_path, [], max_file_size=100)

        assert len(findings) == 1
        assert findings[0].rule_id == "FS-005"
        assert scanned == 0
        assert skipped == 1

    def test_file_within_limit_is_scanned(self, tmp_path: Path) -> None:
        """A file within max_file_size proceeds to rule matching."""
        ok = tmp_path / "ok.py"
        ok.write_text("print('hi')", encoding="utf-8")

        findings, scanned, skipped, _ = scan_all_files([ok], tmp_path, [], max_file_size=1000)

        assert findings == []
        assert scanned > 0
        assert skipped == 0

    def test_zero_max_file_size_disables_check(self, tmp_path: Path) -> None:
        """max_file_size=0 (default) skips the size guard."""
        big = tmp_path / "big.py"
        big.write_text("x" * 200, encoding="utf-8")

        findings, scanned, skipped, _ = scan_all_files([big], tmp_path, [], max_file_size=0)

        assert findings == []
        assert scanned == 200
        assert skipped == 0


def _create_test_files(tmp_path: Path, count: int) -> list[Path]:
    """Create count text files with unique content for scanning."""
    files = []
    for i in range(count):
        f = tmp_path / f"file_{i}.txt"
        f.write_text(f"content line {i}\n", encoding="utf-8")
        files.append(f)
    return files


class TestConcurrentScanning:
    """Concurrent scanning via ProcessPoolExecutor for large file sets."""

    def test_small_file_count_uses_sequential(self, tmp_path: Path) -> None:
        """Below MIN_FILES_FOR_CONCURRENCY, ProcessPoolExecutor is not created."""
        files = _create_test_files(tmp_path, MIN_FILES_FOR_CONCURRENCY - 1)

        with patch("skill_scan.content_scanner.ProcessPoolExecutor") as mock_pool:
            findings, scanned, skipped, _ = scan_all_files(files, tmp_path, [])

        mock_pool.assert_not_called()
        assert scanned > 0
        assert skipped == 0
        assert findings == []

    def test_large_file_count_uses_concurrent(self, tmp_path: Path) -> None:
        """At or above MIN_FILES_FOR_CONCURRENCY, ProcessPoolExecutor is used."""
        files = _create_test_files(tmp_path, MIN_FILES_FOR_CONCURRENCY)

        with patch(
            "skill_scan.content_scanner.ProcessPoolExecutor",
            wraps=_RealProcessPoolExecutor,
        ) as mock_pool:
            _findings, scanned, skipped, _ = scan_all_files(files, tmp_path, [])

        mock_pool.assert_called_once()
        assert scanned > 0
        assert skipped == 0

    def test_concurrent_and_sequential_produce_identical_results(self, tmp_path: Path) -> None:
        """Concurrent results match sequential: same bytes_scanned, files_skipped."""
        files = _create_test_files(tmp_path, MIN_FILES_FOR_CONCURRENCY)

        from skill_scan.content_scanner import _scan_sequential

        seq_findings, seq_bytes, seq_skipped, _ = _scan_sequential(files, tmp_path, [], 0)

        conc_findings, conc_bytes, conc_skipped, _ = scan_all_files(files, tmp_path, [])

        assert conc_bytes == seq_bytes
        assert conc_skipped == seq_skipped
        # Findings are order-independent; compare as sorted sets
        seq_ids = sorted(f.rule_id for f in seq_findings)
        conc_ids = sorted(f.rule_id for f in conc_findings)
        assert conc_ids == seq_ids

    def test_fallback_to_sequential_on_pool_failure(self, tmp_path: Path) -> None:
        """If ProcessPoolExecutor raises RuntimeError, falls back to sequential."""
        files = _create_test_files(tmp_path, MIN_FILES_FOR_CONCURRENCY)

        with patch(
            "skill_scan.content_scanner.ProcessPoolExecutor",
            side_effect=RuntimeError("multiprocessing not supported"),
        ):
            _findings, scanned, skipped, _ = scan_all_files(files, tmp_path, [])

        assert scanned > 0
        assert skipped == 0

    def test_fallback_to_sequential_on_os_error(self, tmp_path: Path) -> None:
        """If ProcessPoolExecutor raises OSError, falls back to sequential."""
        files = _create_test_files(tmp_path, MIN_FILES_FOR_CONCURRENCY)

        with patch(
            "skill_scan.content_scanner.ProcessPoolExecutor",
            side_effect=OSError("cannot fork"),
        ):
            _findings, scanned, skipped, _ = scan_all_files(files, tmp_path, [])

        assert scanned > 0
        assert skipped == 0

    def test_max_workers_is_threaded_through(self, tmp_path: Path) -> None:
        """max_workers parameter reaches ProcessPoolExecutor."""
        files = _create_test_files(tmp_path, MIN_FILES_FOR_CONCURRENCY)

        with patch(
            "skill_scan.content_scanner.ProcessPoolExecutor",
            wraps=_RealProcessPoolExecutor,
        ) as mock_pool:
            scan_all_files(files, tmp_path, [], max_workers=2)

        mock_pool.assert_called_once_with(max_workers=2)


class TestAcceptanceConcurrentVsSequential:
    """Acceptance: concurrent scanning produces same results as sequential."""

    def test_concurrent_matches_sequential(self, tmp_path: Path) -> None:
        """Scan a 20-file skill directory with max_workers=2 and compare."""
        from skill_scan.content_scanner import _scan_sequential
        from skill_scan.rules import load_default_rules

        for i in range(20):
            f = tmp_path / f"file_{i}.py"
            f.write_text(f"x_{i} = 1\nprint('hello {i}')\n", encoding="utf-8")

        rules = load_default_rules()
        file_list = [tmp_path / f"file_{i}.py" for i in range(20)]

        seq_findings, seq_bytes, seq_skipped, seq_suppressed = _scan_sequential(file_list, tmp_path, rules, 0)
        conc_findings, conc_bytes, conc_skipped, conc_suppressed = scan_all_files(
            file_list, tmp_path, rules, max_workers=2
        )

        assert conc_bytes == seq_bytes
        assert conc_skipped == seq_skipped
        assert conc_suppressed == seq_suppressed

        seq_ids = sorted((f.rule_id, f.file, f.line) for f in seq_findings)
        conc_ids = sorted((f.rule_id, f.file, f.line) for f in conc_findings)
        assert conc_ids == seq_ids


class TestMaxWorkersConfig:
    """ScanConfig.max_workers is loadable from TOML and defaults to 0."""

    def test_default_max_workers_is_zero(self) -> None:
        """Default ScanConfig has max_workers=0 (auto-detect)."""
        from skill_scan.config import ScanConfig

        cfg = ScanConfig()
        assert cfg.max_workers == 0

    def test_max_workers_from_toml(self, tmp_path: Path) -> None:
        """max_workers is read from [scan] section in TOML config."""
        from skill_scan.config import load_config

        toml_file = tmp_path / "config.toml"
        toml_file.write_text("[scan]\nmax_workers = 4\n", encoding="utf-8")

        cfg = load_config(toml_file)
        assert cfg.max_workers == 4

    def test_scanner_threads_max_workers(self, tmp_path: Path) -> None:
        """scanner.scan() passes cfg.max_workers to scan_all_files."""
        from skill_scan.config import ScanConfig

        # Create a minimal skill directory
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text("---\nname: test\n---\n", encoding="utf-8")
        sample = tmp_path / "hello.txt"
        sample.write_text("hello", encoding="utf-8")

        cfg = ScanConfig(max_workers=3)

        with patch("skill_scan.scanner.scan_all_files", wraps=scan_all_files) as mock_scan:
            from skill_scan.scanner import scan

            scan(tmp_path, config=cfg)

        _, kwargs = mock_scan.call_args
        assert kwargs["max_workers"] == 3
