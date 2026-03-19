"""Tests for custom ROT13 function detection via chr/ord/% 26 arithmetic (OBFS-001).

Covers: FunctionDef with manual rotation arithmetic (both lowercase and
uppercase branches required), negative cases (module-level code, single branch,
no %26, no chr/ord), and regression guards for existing codecs/maketrans detectors.
"""

from __future__ import annotations

import string

from skill_scan.ast_analyzer import analyze_python
from tests.unit.rule_helpers import filter_by_rule

_FILE = "test.py"
_ids = filter_by_rule

_ROT13_FROM = string.ascii_lowercase + string.ascii_uppercase
_ROT13_TO = "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM"


class TestCustomRot13Detection:
    """Detect FunctionDef containing manual ROT13 chr/ord/%26 arithmetic."""

    def test_standard_custom_rot13_detected(self) -> None:
        """Standard custom ROT13 with both lowercase and uppercase branches."""
        code = """\
def rot13(text):
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)
"""
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity.value == "high"
        assert f.category == "obfuscation"
        assert f.line == 1  # Finding on the FunctionDef line

    def test_rot_n_variant_detected(self) -> None:
        """ROT-N with a different shift value still uses %26 + chr/ord."""
        code = """\
def caesar(s):
    out = []
    for ch in s:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - ord('a') + 7) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - ord('A') + 7) % 26 + ord('A')))
        else:
            out.append(ch)
    return ''.join(out)
"""
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1

    def test_chr_ord_without_mod26_no_finding(self) -> None:
        """chr/ord usage without %26 should NOT trigger (general char math)."""
        code = """\
def shift_char(text):
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr(ord(c) + 1))
        elif 'A' <= c <= 'Z':
            result.append(chr(ord(c) + 1))
        else:
            result.append(c)
    return ''.join(result)
"""
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 0

    def test_mod26_without_chr_ord_no_finding(self) -> None:
        """Arithmetic with %26 but no chr/ord should NOT trigger."""
        code = """\
def index_wrap(text):
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            idx = (int(c) + 13) % 26
            result.append(str(idx))
        elif 'A' <= c <= 'Z':
            idx = (int(c) + 13) % 26
            result.append(str(idx))
    return result
"""
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 0

    def test_bare_code_not_in_function_no_finding(self) -> None:
        """ROT13 arithmetic at module level (not in FunctionDef) should NOT trigger."""
        code = """\
result = []
for c in text:
    if 'a' <= c <= 'z':
        result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
    elif 'A' <= c <= 'Z':
        result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
"""
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 0

    def test_only_lowercase_branch_no_finding(self) -> None:
        """Only lowercase ROT13 branch (missing uppercase) should NOT trigger."""
        code = """\
def rot_lower(text):
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        else:
            result.append(c)
    return ''.join(result)
"""
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 0

    def test_only_uppercase_branch_no_finding(self) -> None:
        """Only uppercase ROT13 branch (missing lowercase) should NOT trigger."""
        code = """\
def rot_upper(text):
    result = []
    for c in text:
        if 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)
"""
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 0

    def test_existing_codecs_rot13_unchanged(self) -> None:
        """Ensure existing codecs ROT13 detection still works (no regression)."""
        code = "import codecs\ncodecs.encode('hello', 'rot_13')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1

    def test_existing_maketrans_rot13_unchanged(self) -> None:
        """Ensure existing maketrans ROT13 detection still works (no regression)."""
        code = f"str.maketrans('{_ROT13_FROM}', '{_ROT13_TO}')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1
