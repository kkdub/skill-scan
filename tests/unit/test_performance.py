"""Performance and ReDoS safety tests for the scanner.

Verifies bounded runtime for adversarial inputs designed to trigger
catastrophic backtracking or O(n^2) behavior in the regex engine.
"""

from __future__ import annotations

import re
import time

import pytest

from skill_scan.normalizer import normalize_line
from skill_scan.rules.engine import match_content, match_line
from skill_scan.rules.loader import _MAX_PATTERN_LENGTH, load_default_rules


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """Collect (rule_id, pattern) pairs from all default rules."""
    pairs: list[tuple[str, re.Pattern[str]]] = []
    for rule in load_default_rules():
        for p in rule.patterns:
            pairs.append((rule.rule_id, p))
        for p in rule.exclude_patterns:
            pairs.append((f"{rule.rule_id}/excl", p))
    return pairs


_REDOS_INPUTS = [
    "a" * 10_000,
    " " * 10_000,
    "\\x41" * 5_000,
    "eval(" * 2_000,
    "A" * 5_000 + "!",
    "/" * 5_000,
    "a]" * 5_000,
    ">" * 5_000 + "<",
    "https://" + "a" * 10_000,
    "subprocess.run(" + "x" * 5_000,
    "base64.b64decode('" + "A" * 5_000 + "')",
    "curl " + "-s " * 2_000 + "-d @file",
    "os.environ" + ".get" * 2_000,
]


# ---------------------------------------------------------------------------
# 1. Long lines
# ---------------------------------------------------------------------------


class TestLongLines:
    """Scanning a file with a single very long line stays bounded."""

    def test_engine_completes_long_line_within_timeout(self) -> None:
        line = "x" * 100_000
        rules = load_default_rules()
        line_rules = [r for r in rules if r.match_scope == "line"]

        start = time.perf_counter()
        match_line(line, 1, "long.py", line_rules)
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0, f"Long-line scan took {elapsed:.2f}s (limit 5s)"

    def test_engine_detects_pattern_in_long_line(self) -> None:
        padding = "x" * 50_000
        line = padding + " eval(user_input) " + padding
        rules = load_default_rules()
        line_rules = [r for r in rules if r.match_scope == "line"]

        findings = match_line(line, 1, "long.py", line_rules)

        assert any("eval" in f.matched_text for f in findings)


# ---------------------------------------------------------------------------
# 2. Large file (500 KB)
# ---------------------------------------------------------------------------


class TestLargeFile:
    """A 500 KB file completes scanning in bounded time."""

    def test_engine_completes_large_file_within_timeout(self) -> None:
        content = ("safe content line\n") * 29_412  # ~500 KB
        rules = load_default_rules()

        start = time.perf_counter()
        match_content(content, "large.py", rules)
        elapsed = time.perf_counter() - start

        assert elapsed < 10.0, f"Large-file scan took {elapsed:.2f}s (limit 10s)"

    def test_engine_finds_pattern_in_large_file(self) -> None:
        lines = ["safe content line\n"] * 5_000
        lines[2_500] = "eval(user_input)\n"
        content = "".join(lines)
        rules = load_default_rules()

        findings = match_content(content, "large.py", rules)

        assert any("eval" in f.matched_text for f in findings)


# ---------------------------------------------------------------------------
# 3. Many short lines
# ---------------------------------------------------------------------------


class TestManyShortLines:
    """10,000 short lines scanned in bounded time (no O(n^2))."""

    def test_engine_completes_many_lines_within_timeout(self) -> None:
        content = "short line\n" * 10_000
        rules = load_default_rules()

        start = time.perf_counter()
        match_content(content, "many.py", rules)
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0, f"Many-lines scan took {elapsed:.2f}s (limit 5s)"


# ---------------------------------------------------------------------------
# 4. ReDoS — every pattern tested against adversarial inputs
# ---------------------------------------------------------------------------

_PATTERN_IDS = _all_patterns()


class TestReDosSafety:
    """Each regex pattern completes in bounded time on adversarial inputs."""

    @pytest.mark.parametrize(
        "rule_id,pattern",
        _PATTERN_IDS,
        ids=[f"{rid}:{p.pattern[:40]}" for rid, p in _PATTERN_IDS],
    )
    def test_pattern_completes_within_timeout(
        self,
        rule_id: str,
        pattern: re.Pattern[str],
    ) -> None:
        for adversarial in _REDOS_INPUTS:
            start = time.perf_counter()
            pattern.search(adversarial)
            elapsed = time.perf_counter() - start

            assert elapsed < 1.0, (
                f"Pattern from {rule_id} took {elapsed:.2f}s (pattern: {pattern.pattern[:60]})"
            )


# ---------------------------------------------------------------------------
# 5. Normalization performance
# ---------------------------------------------------------------------------


class TestNormalizationPerformance:
    """Normalization of large inputs with many Unicode chars stays bounded."""

    def test_normalize_large_mixed_content_within_timeout(self) -> None:
        # 100 KB of alternating normal + zero-width characters
        chunk = "e\u200bv\u200ca\u200dl\u2060(\ufeff)\u00a0"
        content = chunk * (100_000 // len(chunk))

        start = time.perf_counter()
        result = normalize_line(content)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"Normalization took {elapsed:.2f}s (limit 2s)"
        assert "\u200b" not in result
        assert "\u200c" not in result

    def test_normalize_output_correctness_on_large_input(self) -> None:
        content = ("e\u200bval " * 100).strip()
        result = normalize_line(content)
        assert result == ("eval " * 100).strip()


# ---------------------------------------------------------------------------
# 6. Full pipeline stress (multiline + normalization)
# ---------------------------------------------------------------------------


class TestFullPipelineStress:
    """Combined multiline + normalization pipeline stays bounded."""

    def test_pipeline_completes_large_obfuscated_file(self) -> None:
        base_line = "e\u200bv\u200cal(\u00a0input\u00a0)\n"
        content = base_line * 5_000  # ~100 KB with obfuscation
        rules = load_default_rules()

        start = time.perf_counter()
        findings = match_content(content, "obfuscated.py", rules)
        elapsed = time.perf_counter() - start

        assert elapsed < 10.0, f"Pipeline took {elapsed:.2f}s (limit 10s)"
        assert len(findings) > 0, "Should detect eval through normalization"


# ---------------------------------------------------------------------------
# 7. Pattern length validation
# ---------------------------------------------------------------------------


class TestPatternLengthValidation:
    """Loader rejects patterns exceeding max length."""

    def test_loader_rejects_pattern_over_max_length(self) -> None:
        from skill_scan.rules.loader import _compile_patterns

        oversized = "a" * (_MAX_PATTERN_LENGTH + 1)
        with pytest.raises(ValueError, match="Regex pattern too long"):
            _compile_patterns([oversized], re.RegexFlag(0))

    def test_loader_accepts_pattern_at_max_length(self) -> None:
        from skill_scan.rules.loader import _compile_patterns

        exact = "a" * _MAX_PATTERN_LENGTH
        result = _compile_patterns([exact], re.RegexFlag(0))
        assert len(result) == 1
