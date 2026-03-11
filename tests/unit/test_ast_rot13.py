"""Tests for ROT13 AST detection (OBFS-001).

Covers: codecs.encode/decode with 'rot_13'/'rot13', indirect codec access
(getencoder/getdecoder/lookup/iterencode), str.maketrans ROT13 pair,
aliased imports, negative cases, and deduplication.
"""

from __future__ import annotations

import string

import pytest

from skill_scan._ast_rot13 import is_rot13_pair
from skill_scan.ast_analyzer import analyze_python
from skill_scan.content_scanner import _deduplicate
from skill_scan.models import Finding, Severity
from tests.unit.rule_helpers import filter_by_rule

_FILE = "test.py"
_ids = filter_by_rule

_ROT13_FROM = string.ascii_lowercase + string.ascii_uppercase
_ROT13_TO = "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM"


# ---------------------------------------------------------------------------
# is_rot13_pair -- pure function
# ---------------------------------------------------------------------------


class TestIsRot13Pair:
    def test_valid_rot13_lowercase_uppercase(self) -> None:
        assert is_rot13_pair(_ROT13_FROM, _ROT13_TO) is True

    def test_reversed_still_valid(self) -> None:
        assert is_rot13_pair(_ROT13_TO, _ROT13_FROM) is True

    def test_identity_not_rot13(self) -> None:
        alpha = string.ascii_lowercase + string.ascii_uppercase
        assert is_rot13_pair(alpha, alpha) is False

    def test_too_short(self) -> None:
        assert is_rot13_pair("abc", "nop") is False

    def test_different_lengths(self) -> None:
        assert is_rot13_pair(_ROT13_FROM, _ROT13_TO + "x") is False

    def test_wrong_mapping(self) -> None:
        bad_to = "a" + _ROT13_TO[1:]
        assert is_rot13_pair(_ROT13_FROM, bad_to) is False

    def test_degenerate_repeated_chars_rejected(self) -> None:
        """Repeated single letter ('b'*26) must not pass as a full alphabet."""
        assert is_rot13_pair("b" * 26 + "B" * 26, "o" * 26 + "O" * 26) is False


# ---------------------------------------------------------------------------
# codecs.encode / codecs.decode -- R001
# ---------------------------------------------------------------------------


class TestCodecsEncodeDecode:
    @pytest.mark.parametrize("func", ["codecs.encode", "codecs.decode"])
    @pytest.mark.parametrize("variant", ["rot_13", "rot13"])
    def test_direct_call(self, func: str, variant: str) -> None:
        code = f"import codecs\n{func}('hello', '{variant}')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity.value == "high"
        assert f.category == "obfuscation"

    @pytest.mark.parametrize("func", ["codecs.encode", "codecs.decode"])
    def test_safe_encoding_no_finding(self, func: str) -> None:
        code = f"import codecs\n{func}('hello', 'utf-8')\n"
        assert not _ids("OBFS-001", analyze_python(code, _FILE))


# ---------------------------------------------------------------------------
# Indirect codec access -- R002 / R-IMP012
# ---------------------------------------------------------------------------


class TestCodecsIndirect:
    @pytest.mark.parametrize(
        "func",
        [
            "codecs.getencoder",
            "codecs.getdecoder",
            "codecs.lookup",
        ],
    )
    @pytest.mark.parametrize("variant", ["rot_13", "rot13"])
    def test_indirect_with_both_variants(self, func: str, variant: str) -> None:
        code = f"import codecs\n{func}('{variant}')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "OBFS-001"
        assert f.severity.value == "high"
        assert f.category == "obfuscation"

    @pytest.mark.parametrize("variant", ["rot_13", "rot13"])
    def test_iterencode_encoding_at_arg1(self, variant: str) -> None:
        """iterencode(iterator, encoding) — encoding is the 2nd argument."""
        code = f"import codecs\ncodecs.iterencode(data, '{variant}')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1

    def test_iterencode_safe_encoding_no_finding(self) -> None:
        code = "import codecs\ncodecs.iterencode(data, 'utf-8')\n"
        assert not _ids("OBFS-001", analyze_python(code, _FILE))

    def test_iterencode_single_arg_no_finding(self) -> None:
        """iterencode with only 1 arg — encoding missing, should not match."""
        code = "import codecs\ncodecs.iterencode('rot_13')\n"
        assert not _ids("OBFS-001", analyze_python(code, _FILE))

    @pytest.mark.parametrize(
        "func",
        [
            "codecs.getencoder",
            "codecs.getdecoder",
            "codecs.lookup",
        ],
    )
    def test_safe_codec_no_finding(self, func: str) -> None:
        code = f"import codecs\n{func}('utf-8')\n"
        assert not _ids("OBFS-001", analyze_python(code, _FILE))


# ---------------------------------------------------------------------------
# str.maketrans -- R003
# ---------------------------------------------------------------------------


class TestStrMaketrans:
    def test_rot13_pair_detected(self) -> None:
        code = f"table = str.maketrans('{_ROT13_FROM}', '{_ROT13_TO}')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity.value == "high"
        assert f.category == "obfuscation"
        assert "maketrans" in f.matched_text

    def test_non_rot13_pair_no_finding(self) -> None:
        alpha = string.ascii_lowercase + string.ascii_uppercase
        code = f"table = str.maketrans('{alpha}', '{alpha}')\n"
        assert not _ids("OBFS-001", analyze_python(code, _FILE))

    def test_unresolvable_args_no_finding(self) -> None:
        code = "table = str.maketrans(from_chars, to_chars)\n"
        assert not _ids("OBFS-001", analyze_python(code, _FILE))

    def test_single_arg_no_finding(self) -> None:
        code = "table = str.maketrans({'a': 'n'})\n"
        assert not _ids("OBFS-001", analyze_python(code, _FILE))


# ---------------------------------------------------------------------------
# Aliased imports -- alias_map resolution
# ---------------------------------------------------------------------------


class TestAliasedImports:
    def test_codecs_alias_encode(self) -> None:
        code = "import codecs as c\nc.encode('hello', 'rot_13')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1

    def test_codecs_alias_decode(self) -> None:
        code = "import codecs as c\nc.decode('uryyb', 'rot13')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1

    def test_codecs_alias_getencoder(self) -> None:
        code = "import codecs as c\nc.getencoder('rot_13')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Finding metadata -- R004
# ---------------------------------------------------------------------------


class TestFindingMetadata:
    def test_all_codec_findings_have_correct_metadata(self) -> None:
        code = "import codecs\ncodecs.encode('x', 'rot_13')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "OBFS-001"
        assert f.severity.value == "high"
        assert f.category == "obfuscation"

    def test_maketrans_finding_has_correct_metadata(self) -> None:
        code = f"str.maketrans('{_ROT13_FROM}', '{_ROT13_TO}')\n"
        findings = _ids("OBFS-001", analyze_python(code, _FILE))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "OBFS-001"
        assert f.severity.value == "high"
        assert f.category == "obfuscation"


# ---------------------------------------------------------------------------
# Deduplication -- R-IMP013
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_deduplicate_same_line(self) -> None:
        f1 = Finding(
            rule_id="OBFS-001",
            severity=Severity.HIGH,
            category="obfuscation",
            file="test.py",
            line=1,
            matched_text="a",
            description="d1",
            recommendation="r1",
        )
        f2 = Finding(
            rule_id="OBFS-001",
            severity=Severity.HIGH,
            category="obfuscation",
            file="test.py",
            line=1,
            matched_text="b",
            description="d2",
            recommendation="r2",
        )
        result = _deduplicate([], [f1, f2])
        obfs = [f for f in result if f.rule_id == "OBFS-001"]
        assert len(obfs) == 1
