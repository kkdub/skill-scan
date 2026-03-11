"""Tests for URL-encoded and unicode-escape decoder extraction and decoding."""

from __future__ import annotations

from pathlib import Path

from skill_scan.ast_analyzer import analyze_python
from skill_scan.content_scanner import scan_all_files
from skill_scan.decoder import (
    EncodedPayload,
    _UNICODE_ESCAPE_RE,
    _URL_ENCODED_RE,
    _decode_unicode_escape,
    _decode_url_encoded,
    _extract_unicode_escape_from_line,
    _extract_url_encoded_from_line,
    decode_payload,
    extract_encoded_strings,
)
from skill_scan.rules import load_default_rules


def _make_payload(text: str, encoding: str) -> EncodedPayload:
    """Construct an EncodedPayload with default line/offset for unit tests."""
    return EncodedPayload(encoded_text=text, encoding_type=encoding, line_num=1, start_offset=0)


class TestExtractUrlEncoded:
    """URL-encoded payload extraction from content lines."""

    def test_three_consecutive_percent_encoded(self) -> None:
        """Extracts 3+ consecutive %XX sequences."""
        payloads = _extract_url_encoded_from_line("data = %65%76%61%6C%28%29", 1)
        assert len(payloads) == 1
        assert payloads[0].encoded_text == "%65%76%61%6C%28%29"
        assert payloads[0].encoding_type == "url"
        assert payloads[0].line_num == 1

    def test_two_percent_encoded_not_extracted(self) -> None:
        """Fewer than 3 consecutive %XX sequences are not extracted."""
        assert len(_extract_url_encoded_from_line("path = %20%21", 1)) == 0

    def test_extract_encoded_strings_finds_url(self) -> None:
        """extract_encoded_strings() finds URL-encoded payloads."""
        payloads = extract_encoded_strings("payload = %65%76%61%6C%28%29\n")
        url_payloads = [p for p in payloads if p.encoding_type == "url"]
        assert len(url_payloads) >= 1
        assert url_payloads[0].encoded_text == "%65%76%61%6C%28%29"

    def test_multiline_url_extraction(self) -> None:
        """Extracts URL-encoded payloads from multiple lines."""
        content = "line1 = %41%42%43\nline2 = normal\nline3 = %44%45%46"
        url_payloads = [p for p in extract_encoded_strings(content) if p.encoding_type == "url"]
        assert len(url_payloads) == 2
        assert url_payloads[0].line_num == 1
        assert url_payloads[1].line_num == 3

    def test_start_offset_correct(self) -> None:
        """start_offset points to the start of the encoded text."""
        payloads = _extract_url_encoded_from_line("prefix %41%42%43 suffix", 1)
        assert len(payloads) == 1
        assert payloads[0].start_offset == 7

    def test_url_regex_exported_from_decoder(self) -> None:
        """_URL_ENCODED_RE is re-exported from decoder.py."""
        assert _URL_ENCODED_RE is not None
        assert _URL_ENCODED_RE.search("%41%42%43") is not None


class TestExtractUnicodeEscape:
    r"""Unicode-escape payload extraction (\uXXXX / \UXXXXXXXX)."""

    def test_three_consecutive_unicode_escapes(self) -> None:
        r"""Extracts 3+ consecutive \uXXXX sequences."""
        payloads = _extract_unicode_escape_from_line(r"data = \u0065\u0076\u0061\u006C", 1)
        assert len(payloads) == 1
        assert payloads[0].encoded_text == r"\u0065\u0076\u0061\u006C"
        assert payloads[0].encoding_type == "unicode_escape"
        assert payloads[0].line_num == 1

    def test_two_unicode_escapes_not_extracted(self) -> None:
        r"""Fewer than 3 consecutive \uXXXX are not extracted."""
        assert len(_extract_unicode_escape_from_line(r"x = \u0041\u0042", 1)) == 0

    def test_big_u_escapes(self) -> None:
        r"""Extracts 3+ consecutive \UXXXXXXXX sequences."""
        payloads = _extract_unicode_escape_from_line(r"data = \U00000065\U00000076\U00000061", 1)
        assert len(payloads) == 1
        assert payloads[0].encoding_type == "unicode_escape"

    def test_mixed_u_and_U(self) -> None:
        r"""Extracts mixed \uXXXX and \UXXXXXXXX sequences."""
        assert len(_extract_unicode_escape_from_line(r"data = \u0065\U00000076\u0061", 1)) == 1

    def test_extract_encoded_strings_finds_unicode(self) -> None:
        r"""extract_encoded_strings() finds unicode-escape payloads."""
        content = r"payload = \u0065\u0076\u0061\u006C" + "\n"
        uni_payloads = [p for p in extract_encoded_strings(content) if p.encoding_type == "unicode_escape"]
        assert len(uni_payloads) >= 1

    def test_unicode_regex_exported_from_decoder(self) -> None:
        """_UNICODE_ESCAPE_RE is re-exported from decoder.py."""
        assert _UNICODE_ESCAPE_RE is not None
        assert _UNICODE_ESCAPE_RE.search(r"\u0041\u0042\u0043") is not None


class TestDecodeUrlEncoded:
    """URL-encoded payload decoding."""

    def test_decode_url_encoded_eval(self) -> None:
        """Decodes %XX sequences to plain text."""
        assert _decode_url_encoded("%65%76%61%6C%28%29") == "eval()"

    def test_decode_payload_url_returns_str(self) -> None:
        """decode_payload() returns str (not bytes) for encoding_type='url'."""
        result = decode_payload(_make_payload("%65%76%61%6C%28%29", "url"))
        assert result == "eval()"
        assert isinstance(result, str)

    def test_decode_payload_url_depth_limit(self) -> None:
        """decode_payload() returns None when depth >= MAX_DECODE_DEPTH."""
        assert decode_payload(_make_payload("%65%76%61%6C", "url"), depth=2) is None

    def test_decode_url_mixed_encoded_literal(self) -> None:
        """Handles mix of encoded and literal characters."""
        assert _decode_url_encoded("%65val%28%29") == "eval()"


class TestDecodeUnicodeEscape:
    r"""Unicode-escape payload decoding (\uXXXX)."""

    def test_decode_unicode_escape_eval(self) -> None:
        r"""Decodes \uXXXX sequences to plain text."""
        assert _decode_unicode_escape(r"\u0065\u0076\u0061\u006C") == "eval"

    def test_decode_payload_unicode_returns_str(self) -> None:
        """decode_payload() returns str for encoding_type='unicode_escape'."""
        result = decode_payload(_make_payload(r"\u0065\u0076\u0061\u006C", "unicode_escape"))
        assert result == "eval"
        assert isinstance(result, str)

    def test_decode_payload_unicode_depth_limit(self) -> None:
        """decode_payload() returns None when depth >= MAX_DECODE_DEPTH."""
        assert decode_payload(_make_payload(r"\u0065\u0076\u0061", "unicode_escape"), depth=2) is None

    def test_decode_big_u_escapes(self) -> None:
        r"""Decodes \UXXXXXXXX sequences."""
        assert _decode_unicode_escape(r"\U00000065\U00000076\U00000061") == "eva"


class TestNoExternalDeps:
    """Verify no new external dependencies were introduced."""

    def test_decoder_url_unicode_uses_stdlib_only(self) -> None:
        """_decoder_url_unicode.py only uses stdlib imports."""
        import inspect

        import skill_scan._decoder_url_unicode as mod

        source = inspect.getsource(mod)
        assert "urllib.parse" in source
        assert "requests" not in source
        assert "httpx" not in source


class TestAcceptanceScenarios:
    """Plan-level acceptance tests exercising full feature paths."""

    def test_rot13_obfuscation_detected_via_ast_aliased_import(self) -> None:
        """ROT13 obfuscation in Python detected via AST with aliased import.

        OBFS-001 is AST-only (no regex counterpart), so tested via
        analyze_python() rather than scan_all_files().
        """
        code = 'import codecs as c\nc.encode(secret, "rot_13")\n'
        findings = analyze_python(code, "rot13_alias.py")
        obfs001 = [f for f in findings if f.rule_id == "OBFS-001"]
        assert len(obfs001) >= 1, f"Expected OBFS-001, got: {[f.rule_id for f in findings]}"
        assert obfs001[0].severity.value == "high"
        assert obfs001[0].category == "obfuscation"

    def test_url_encoded_payload_extracted_decoded_scanned(self, tmp_path: Path) -> None:
        """URL-encoded eval() extracted, decoded, and triggers EXEC-002 via Pass 4."""
        content = "payload = %65%76%61%6C%28%29\n"
        txt_file = tmp_path / "encoded.txt"
        txt_file.write_text(content, encoding="utf-8")
        rules = load_default_rules()
        findings, _, _, _ = scan_all_files([txt_file], tmp_path, rules)
        rule_ids = [f.rule_id for f in findings]
        assert "OBFS-002" in rule_ids, f"Expected OBFS-002, got: {rule_ids}"
        decoded_exec = [f for f in findings if f.rule_id == "EXEC-002" and "[decoded]" in f.description]
        assert len(decoded_exec) >= 1, (
            f"Expected [decoded] EXEC-002, got: {[(f.rule_id, f.description) for f in findings]}"
        )

    def test_unicode_escape_extracted_and_decoded(self) -> None:
        r"""Unicode escape sequences extracted and decoded to 'eval'."""
        content = r"\u0065\u0076\u0061\u006C"
        uni_payloads = [p for p in extract_encoded_strings(content) if p.encoding_type == "unicode_escape"]
        assert len(uni_payloads) >= 1, (
            f"Expected unicode_escape payload, got types: {[p.encoding_type for p in extract_encoded_strings(content)]}"
        )
        assert decode_payload(uni_payloads[0]) == "eval"
