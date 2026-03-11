"""Integration tests for dataflow analysis wired into analyze_python().

Verifies that build_symbol_table and detect_split_evasion are called by
analyze_python() and produce findings for split-variable evasion patterns.
Also verifies facade re-exports and no regressions on existing detectors.
"""

from __future__ import annotations

import base64
import textwrap

from skill_scan.ast_analyzer import (
    analyze_python,
    build_symbol_table,
    detect_split_evasion,
)
from skill_scan.models import Severity


class TestFacadeReexports:
    """Verify build_symbol_table and detect_split_evasion are re-exported."""

    def test_build_symbol_table_importable(self) -> None:
        assert callable(build_symbol_table)

    def test_detect_split_evasion_importable(self) -> None:
        assert callable(detect_split_evasion)


class TestAnalyzePythonSplitEvasion:
    """Integration: analyze_python() detects split-variable evasion."""

    def test_concat_exec_detected(self) -> None:
        source = textwrap.dedent("""\
            a = "ex"
            b = "ec"
            result = a + b
        """)
        findings = analyze_python(source, "test.py")
        split_findings = [f for f in findings if "split" in f.matched_text]
        assert len(split_findings) == 1
        assert split_findings[0].rule_id == "EXEC-002"
        assert split_findings[0].severity == Severity.CRITICAL

    def test_concat_import_detected(self) -> None:
        source = textwrap.dedent("""\
            x = "__imp"
            y = "ort__"
            z = x + y
        """)
        findings = analyze_python(source, "test.py")
        split_findings = [f for f in findings if "split" in f.matched_text]
        assert len(split_findings) == 1
        assert split_findings[0].rule_id == "EXEC-006"
        assert split_findings[0].severity == Severity.HIGH

    def test_fstring_eval_detected(self) -> None:
        source = textwrap.dedent("""\
            a = "ev"
            b = "al"
            c = f"{a}{b}"
        """)
        findings = analyze_python(source, "test.py")
        split_findings = [f for f in findings if "split" in f.matched_text]
        assert len(split_findings) == 1
        assert split_findings[0].rule_id == "EXEC-002"

    def test_join_exec_detected(self) -> None:
        source = textwrap.dedent("""\
            a = "ex"
            b = "ec"
            c = "".join([a, b])
        """)
        findings = analyze_python(source, "test.py")
        split_findings = [f for f in findings if "split" in f.matched_text]
        assert len(split_findings) >= 1
        assert split_findings[0].rule_id == "EXEC-002"

    def test_no_false_positive_safe_concat(self) -> None:
        source = textwrap.dedent("""\
            a = "hello"
            b = "world"
            c = a + b
        """)
        findings = analyze_python(source, "test.py")
        split_findings = [f for f in findings if "split" in f.matched_text]
        assert len(split_findings) == 0

    def test_line_number_preserved(self) -> None:
        source = textwrap.dedent("""\
            a = "ex"
            b = "ec"
            result = a + b
        """)
        findings = analyze_python(source, "test.py")
        split_findings = [f for f in findings if "split" in f.matched_text]
        assert len(split_findings) == 1
        assert split_findings[0].line == 3

    def test_file_path_preserved(self) -> None:
        source = textwrap.dedent("""\
            a = "ex"
            b = "ec"
            result = a + b
        """)
        findings = analyze_python(source, "skills/bad.py")
        split_findings = [f for f in findings if "split" in f.matched_text]
        assert len(split_findings) == 1
        assert split_findings[0].file == "skills/bad.py"


class TestNoRegressions:
    """Verify existing detectors still produce findings unchanged."""

    def test_direct_exec_still_detected(self) -> None:
        source = 'exec("print(1)")\n'
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_direct_import_still_detected(self) -> None:
        source = '__import__("os")\n'
        findings = analyze_python(source, "test.py")
        exec_findings = [f for f in findings if f.rule_id == "EXEC-006"]
        assert len(exec_findings) >= 1

    def test_parse_error_still_returns_info(self) -> None:
        source = "def broken(:\n"
        findings = analyze_python(source, "test.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "AST-PARSE"
        assert findings[0].severity == Severity.INFO

    def test_return_type_is_list_of_finding(self) -> None:
        source = "x = 1\n"
        findings = analyze_python(source, "test.py")
        assert isinstance(findings, list)


class TestDecoderBridge:
    """Integration: split base64 payloads decoded and checked for danger."""

    def test_split_base64_import_os_detected(self) -> None:
        # Payload must be >= 20 chars encoded (MIN_ENCODED_LENGTH)
        # "import os; os.system('cmd')" -> base64, split across vars
        encoded = base64.b64encode(b"import os; os.system('cmd')").decode()
        assert len(encoded) >= 20  # guard: ensure payload meets minimum
        half = len(encoded) // 2
        source = textwrap.dedent(f"""\
            a = "{encoded[:half]}"
            b = "{encoded[half:]}"
            payload = a + b
        """)
        findings = analyze_python(source, "test.py")
        encoded_findings = [f for f in findings if "encoded" in f.matched_text]
        assert len(encoded_findings) >= 1
        assert encoded_findings[0].rule_id == "EXEC-002"
        assert encoded_findings[0].severity == Severity.CRITICAL

    def test_split_base64_exec_detected(self) -> None:
        # "exec(malicious_payload_here)" -> base64 -> split
        encoded = base64.b64encode(b"exec(malicious_payload_here)").decode()
        assert len(encoded) >= 20
        half = len(encoded) // 2
        source = textwrap.dedent(f"""\
            x = "{encoded[:half]}"
            y = "{encoded[half:]}"
            cmd = x + y
        """)
        findings = analyze_python(source, "test.py")
        encoded_findings = [f for f in findings if "encoded" in f.matched_text]
        assert len(encoded_findings) >= 1
        assert encoded_findings[0].rule_id == "EXEC-002"

    def test_no_fragment_individually_dangerous(self) -> None:
        # Verify neither fragment alone triggers detection (R-ADV001)
        encoded = base64.b64encode(b"import os; os.system('cmd')").decode()
        half = len(encoded) // 2
        part1 = encoded[:half]
        part2 = encoded[half:]
        # Each fragment alone should produce no split findings
        source_a = f'x = "{part1}"\n'
        source_b = f'x = "{part2}"\n'
        findings_a = analyze_python(source_a, "test.py")
        findings_b = analyze_python(source_b, "test.py")
        split_a = [f for f in findings_a if "split" in f.matched_text or "encoded" in f.matched_text]
        split_b = [f for f in findings_b if "split" in f.matched_text or "encoded" in f.matched_text]
        assert len(split_a) == 0
        assert len(split_b) == 0

    def test_safe_base64_no_false_positive(self) -> None:
        # base64 of safe text should NOT trigger (no dangerous name)
        encoded = base64.b64encode(b"hello world this is safe text").decode()
        assert len(encoded) >= 20
        half = len(encoded) // 2
        source = textwrap.dedent(f"""\
            a = "{encoded[:half]}"
            b = "{encoded[half:]}"
            c = a + b
        """)
        findings = analyze_python(source, "test.py")
        encoded_findings = [f for f in findings if "encoded" in f.matched_text]
        assert len(encoded_findings) == 0


class TestFunctionScopedSplit:
    """Verify function-scoped variables are tracked for split evasion."""

    def test_module_scope_concat_detected(self) -> None:
        """Module-level variables are tracked by bare name and detected."""
        source = textwrap.dedent("""\
            a = "ex"
            b = "ec"
            result = a + b
        """)
        findings = analyze_python(source, "test.py")
        split_findings = [f for f in findings if "split" in f.matched_text]
        assert len(split_findings) == 1
        assert split_findings[0].rule_id == "EXEC-002"

    def test_function_scope_no_crash(self) -> None:
        """Function-scoped vars keyed as 'func.var' -- bare Name won't match.

        This is a known limitation: symbol table uses prefixed keys for
        function-scoped vars, but ast.walk sees bare Names. Verify no crash.
        """
        source = textwrap.dedent("""\
            def attack():
                a = "ex"
                b = "ec"
                result = a + b
        """)
        findings = analyze_python(source, "test.py")
        assert isinstance(findings, list)
