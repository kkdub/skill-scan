"""Evasion corpus effectiveness tests and acceptance scenarios.

Parametrized tests read corpus files from tests/fixtures/split_evasion/,
run analyze_python() on each, and verify detection rate >= 90% on positive
cases and zero false positives on negative cases.

Acceptance scenarios exercise the full feature path for plan-018.
"""

from __future__ import annotations

import base64
import textwrap
from pathlib import Path

import pytest

from skill_scan.ast_analyzer import analyze_python

CORPUS_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "split_evasion"

# Collect corpus files by prefix
_POSITIVE_FILES = sorted(CORPUS_DIR.glob("pos_*.py"))
_NEGATIVE_FILES = sorted(CORPUS_DIR.glob("neg_*.py"))


def _corpus_id(p: Path) -> str:
    return p.stem


class TestCorpusPositive:
    """Each positive corpus file must produce at least one split/encoded finding."""

    @pytest.mark.parametrize("corpus_file", _POSITIVE_FILES, ids=_corpus_id)
    def test_positive_detected(self, corpus_file: Path) -> None:
        source = corpus_file.read_text(encoding="utf-8")
        findings = analyze_python(source, str(corpus_file))
        split_findings = [f for f in findings if "split" in f.matched_text or "encoded" in f.matched_text]
        assert len(split_findings) >= 1, f"Expected detection in {corpus_file.name}, got {findings}"

    def test_detection_rate_above_90_percent(self) -> None:
        """Aggregate: at least 90% of positive corpus cases detected."""
        detected = 0
        total = len(_POSITIVE_FILES)
        assert total >= 10, f"Need >= 10 positive cases, found {total}"
        for corpus_file in _POSITIVE_FILES:
            source = corpus_file.read_text(encoding="utf-8")
            findings = analyze_python(source, str(corpus_file))
            split_findings = [f for f in findings if "split" in f.matched_text or "encoded" in f.matched_text]
            if split_findings:
                detected += 1
        rate = detected / total
        assert rate >= 0.9, f"Detection rate {rate:.0%} ({detected}/{total}) < 90%"


class TestCorpusNegative:
    """Each negative corpus file must produce zero split/encoded findings."""

    @pytest.mark.parametrize("corpus_file", _NEGATIVE_FILES, ids=_corpus_id)
    def test_negative_no_false_positive(self, corpus_file: Path) -> None:
        source = corpus_file.read_text(encoding="utf-8")
        findings = analyze_python(source, str(corpus_file))
        split_findings = [f for f in findings if "split" in f.matched_text or "encoded" in f.matched_text]
        assert len(split_findings) == 0, f"False positive in {corpus_file.name}: {split_findings}"

    def test_minimum_negative_corpus_size(self) -> None:
        """Guard: corpus must have at least 3 negative cases."""
        assert len(_NEGATIVE_FILES) >= 3, f"Need >= 3 negative cases, found {len(_NEGATIVE_FILES)}"


class TestCorpusAdversarial:
    """R-ADV001: individually benign fragments combine to dangerous."""

    def test_no_fragment_individually_dangerous(self) -> None:
        """Verify 'ev' and 'al' are safe alone, but 'eval' triggers."""
        source_a = 'x = "ev"\n'
        source_b = 'x = "al"\n'
        findings_a = analyze_python(source_a, "frag_a.py")
        findings_b = analyze_python(source_b, "frag_b.py")
        split_a = [f for f in findings_a if "split" in f.matched_text]
        split_b = [f for f in findings_b if "split" in f.matched_text]
        assert len(split_a) == 0, "Fragment 'ev' should not trigger"
        assert len(split_b) == 0, "Fragment 'al' should not trigger"
        # Combined triggers
        combined = textwrap.dedent("""\
            a = "ev"
            b = "al"
            x = a + b
        """)
        findings = analyze_python(combined, "combined.py")
        split_f = [f for f in findings if "split" in f.matched_text]
        assert len(split_f) >= 1, "Combined 'eval' should trigger"


class TestCorpusThreeVariable:
    """R-ADV002: three-variable splits are detected."""

    def test_three_var_eval(self) -> None:
        source = textwrap.dedent("""\
            a = "e"
            b = "va"
            c = "l"
            x = a + b + c
        """)
        findings = analyze_python(source, "three_var.py")
        split_f = [f for f in findings if "split" in f.matched_text]
        assert len(split_f) >= 1
        assert split_f[0].rule_id == "EXEC-002"

    def test_three_var_system(self) -> None:
        source = textwrap.dedent("""\
            p1 = "sy"
            p2 = "ste"
            p3 = "m"
            cmd = p1 + p2 + p3
        """)
        findings = analyze_python(source, "three_var.py")
        split_f = [f for f in findings if "split" in f.matched_text]
        assert len(split_f) >= 1
        assert split_f[0].rule_id == "EXEC-002"


class TestAcceptanceScenarios:
    """Plan-level acceptance scenarios for the full feature path."""

    def test_split_concat_eval_full_pipeline(self) -> None:
        """Split variable concatenation building 'eval' detected."""
        source = textwrap.dedent("""\
            a = "ev"
            b = "al"
            x = a + b
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("eval" in f.matched_text for f in exec_findings)

    def test_split_base64_decoder_bridge(self) -> None:
        """Split base64-encoded payload detected via decoder bridge."""
        encoded = base64.b64encode(b"import os; os.system('cmd')").decode()
        assert len(encoded) >= 20  # MIN_ENCODED_LENGTH guard
        half = len(encoded) // 2
        source = textwrap.dedent(f"""\
            a = "{encoded[:half]}"
            b = "{encoded[half:]}"
            payload = a + b
        """)
        findings = analyze_python(source, "test.py")
        encoded_f = [f for f in findings if "encoded" in f.matched_text]
        assert len(encoded_f) >= 1

    def test_safe_concat_no_false_positive(self) -> None:
        """Safe string concatenation produces no false positive."""
        source = textwrap.dedent("""\
            greeting = "hello"
            name = "world"
            msg = greeting + name
        """)
        findings = analyze_python(source, "test.py")
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0


class TestCallReturnAcceptance:
    """Plan-level acceptance scenarios for call-return resolution."""

    def test_inline_call_return_concat_to_eval(self) -> None:
        """Function return values used inline to build a dangerous name are detected."""
        source = textwrap.dedent("""\
            def get_prefix():
                return "ev"
            def get_suffix():
                return "al"
            result = get_prefix() + get_suffix()
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("eval" in f.description for f in exec_findings)

    def test_class_method_self_call_to_popen(self) -> None:
        """Class method return values used via self.method() are detected."""
        source = textwrap.dedent("""\
            class Exploit:
                def prefix(self):
                    return "po"
                def suffix(self):
                    return "pen"
                def run(self):
                    cmd = self.prefix() + self.suffix()
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("popen" in f.description for f in exec_findings)

    def test_double_indirection_call_assign_then_concat(self) -> None:
        """Double-indirection (call-site assignment then variable concatenation) is detected."""
        source = textwrap.dedent("""\
            def get_prefix():
                return "ev"
            def get_suffix():
                return "al"
            x = get_prefix()
            y = get_suffix()
            result = x + y
        """)
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1
        assert any("eval" in f.description for f in exec_findings)
