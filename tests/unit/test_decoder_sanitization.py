"""Tests for decoder sanitization — surrogate stripping and null-byte removal."""

from __future__ import annotations

from skill_scan.decoder import (
    _decode_unicode_escape,
    _decode_url_encoded,
    decode_payload,
)

from .rule_helpers import make_encoded_payload as _make_payload


class TestUrlEncodedNullByteSanitization:
    """Null-byte stripping in URL-encoded decoding (R002, R-IMP003, R-IMP004)."""

    def test_null_bytes_stripped_from_decoded_output(self) -> None:
        """Null bytes (%00) are removed from decoded output."""
        # "e\x00v\x00a\x00l" with null bytes interspersed
        result = _decode_url_encoded("%65%00%76%00%61%00%6C")
        assert "\x00" not in result
        assert result == "eval"

    def test_null_byte_only_payload(self) -> None:
        """Payload of only null bytes decodes to empty string."""
        assert _decode_url_encoded("%00%00%00") == ""

    def test_non_null_characters_preserved(self) -> None:
        """Non-null characters are preserved unchanged."""
        result = _decode_url_encoded("%41%42%43")
        assert result == "ABC"

    def test_null_interspersed_enables_name_detection(self) -> None:
        """Null-interspersed 'eval' decoded cleanly for downstream matching."""
        # e%00v%00a%00l%00(%00)
        result = _decode_url_encoded("%65%00%76%00%61%00%6C%00%28%00%29")
        assert result == "eval()"

    def test_decode_payload_url_strips_nulls(self) -> None:
        """decode_payload() with url type also strips nulls (via _decode_url_encoded)."""
        payload = _make_payload("%65%00%76%00%61%00%6C", "url")
        result = decode_payload(payload)
        assert result == "eval"
        assert "\x00" not in result


class TestUnicodeEscapeSurrogateSanitization:
    """Surrogate stripping in unicode-escape decoding (R001, R-IMP001, R-IMP002)."""

    def test_high_surrogate_d800_stripped(self) -> None:
        r"""U+D800 (first high surrogate) is stripped from output."""
        # \uD800 between 'e' and 'v'
        result = _decode_unicode_escape(r"\u0065\uD800\u0076\u0061\u006C")
        assert result == "eval"
        assert not any(0xD800 <= ord(c) <= 0xDFFF for c in result)

    def test_low_surrogate_dc00_stripped(self) -> None:
        r"""U+DC00 (first low surrogate) is stripped from output."""
        result = _decode_unicode_escape(r"\u0065\uDC00\u0076\u0061\u006C")
        assert result == "eval"

    def test_last_surrogate_dfff_stripped(self) -> None:
        r"""U+DFFF (last surrogate) is stripped from output."""
        result = _decode_unicode_escape(r"\u0065\uDFFF\u0076\u0061\u006C")
        assert result == "eval"

    def test_all_surrogates_stripped_no_exception(self) -> None:
        r"""Payload of only surrogates decodes to empty string without error."""
        result = _decode_unicode_escape(r"\uD800\uDBFF\uDC00\uDFFF")
        assert result == ""

    def test_non_surrogate_characters_preserved(self) -> None:
        r"""Non-surrogate characters pass through unchanged."""
        result = _decode_unicode_escape(r"\u0048\u0065\u006C\u006C\u006F")
        assert result == "Hello"

    def test_surrogate_mixed_payload_produces_clean_string(self) -> None:
        r"""Surrogate-mixed 'eval' produces surrogate-free string for matching."""
        # e + D800 + v + DBFF + a + DC00 + l + DFFF
        result = _decode_unicode_escape(r"\u0065\uD800\u0076\uDBFF\u0061\uDC00\u006C\uDFFF")
        assert result == "eval"
        assert not any(0xD800 <= ord(c) <= 0xDFFF for c in result)

    def test_decode_payload_unicode_strips_surrogates(self) -> None:
        """decode_payload() with unicode_escape type also strips surrogates."""
        payload = _make_payload(r"\u0065\uD800\u0076\u0061\u006C", "unicode_escape")
        result = decode_payload(payload)
        assert result == "eval"
        assert not any(0xD800 <= ord(c) <= 0xDFFF for c in result)
