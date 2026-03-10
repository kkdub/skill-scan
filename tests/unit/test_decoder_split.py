"""Tests for decoder.py / _decoder_helpers.py module split.

Verifies that the Facade Re-export Pattern preserves all import paths
and that both modules contain the expected names.
"""

from __future__ import annotations

import base64
import re

import pytest

from skill_scan.decoder import (
    MAX_DECODE_DEPTH,
    MAX_DECODED_SIZE,
    MIN_ENCODED_LENGTH,
    EncodedPayload,
    _BASE64_RE,
    _HEX_BLOCK_RE,
    _HEX_ESCAPE_RE,
    _HEX_FROMHEX_RE,
    _HB,
    _HF,
    _L,
    _L_B64,
    _decode_base64,
    _decode_bytes,
    _decode_hex,
    _extract_base64_from_line,
    _extract_hex_from_line,
    decode_payload,
    extract_encoded_strings,
)


class TestDecoderReExports:
    """All previously-public names remain importable from skill_scan.decoder."""

    def test_regex_constants_are_compiled(self) -> None:
        """Regex constants re-exported from decoder are compiled Pattern objects."""
        assert isinstance(_BASE64_RE, re.Pattern)
        assert isinstance(_HEX_FROMHEX_RE, re.Pattern)
        assert isinstance(_HEX_ESCAPE_RE, re.Pattern)
        assert isinstance(_HEX_BLOCK_RE, re.Pattern)

    def test_derived_constants_match_min_encoded_length(self) -> None:
        """Derived shorthand constants are consistent with MIN_ENCODED_LENGTH."""
        assert _L == MIN_ENCODED_LENGTH
        assert _L_B64 == max(1, MIN_ENCODED_LENGTH - 3)
        assert _HB == MIN_ENCODED_LENGTH // 2
        assert _HF == MIN_ENCODED_LENGTH // 2 - 1

    def test_public_constants_importable(self) -> None:
        """Public constants are directly importable from decoder."""
        assert MIN_ENCODED_LENGTH == 20
        assert MAX_DECODED_SIZE == 100_000
        assert MAX_DECODE_DEPTH == 2

    def test_encoded_payload_importable(self) -> None:
        """EncodedPayload dataclass is importable from decoder."""
        p = EncodedPayload("abc", "base64", 1, 0)
        assert p.encoded_text == "abc"
        assert p.encoding_type == "base64"

    def test_private_helpers_importable(self) -> None:
        """Private extraction/decode helpers are importable from decoder."""
        assert callable(_extract_base64_from_line)
        assert callable(_extract_hex_from_line)
        assert callable(_decode_bytes)
        assert callable(_decode_base64)
        assert callable(_decode_hex)


class TestDecoderHelpersModule:
    """_decoder_helpers.py contains the expected internal implementations."""

    def test_helpers_module_importable(self) -> None:
        """The _decoder_helpers module can be imported directly."""
        import skill_scan._decoder_helpers as dh

        assert hasattr(dh, "_BASE64_RE")
        assert hasattr(dh, "_extract_base64_from_line")
        assert hasattr(dh, "_decode_bytes")

    def test_helpers_base64_extraction_works(self) -> None:
        """_extract_base64_from_line in helpers produces correct results."""
        encoded = base64.b64encode(b"test payload data here!").decode()
        line = f'x = "{encoded}"'

        results = _extract_base64_from_line(line, 5)

        assert len(results) == 1
        assert results[0].encoding_type == "base64"
        assert results[0].line_num == 5
        assert results[0].encoded_text == encoded

    def test_helpers_hex_extraction_works(self) -> None:
        """_extract_hex_from_line in helpers produces correct results."""
        hex_str = b"hello world, test data!".hex()
        line = f"data = bytes.fromhex('{hex_str}')"

        results = _extract_hex_from_line(line, 3)

        assert len(results) == 1
        assert results[0].encoding_type == "hex"
        assert results[0].line_num == 3

    def test_helpers_decode_base64_works(self) -> None:
        """_decode_base64 from helpers decodes correctly."""
        encoded = base64.b64encode(b"decode me please!!").decode()
        result = _decode_base64(encoded)
        assert result == b"decode me please!!"

    def test_helpers_decode_hex_works(self) -> None:
        """_decode_hex from helpers decodes correctly."""
        hex_str = b"decoded hex ok".hex()
        result = _decode_hex(hex_str)
        assert result == b"decoded hex ok"

    def test_helpers_decode_bytes_dispatches(self) -> None:
        """_decode_bytes dispatches to base64 or hex decoder."""
        b64_text = base64.b64encode(b"dispatch test base64!").decode()
        p_b64 = EncodedPayload(b64_text, "base64", 1, 0)
        assert _decode_bytes(p_b64) == b"dispatch test base64!"

        hex_text = b"dispatch test hex!!".hex()
        p_hex = EncodedPayload(hex_text, "hex", 1, 0)
        assert _decode_bytes(p_hex) == b"dispatch test hex!!"

    def test_helpers_decode_bytes_unknown_returns_none(self) -> None:
        """_decode_bytes returns None for unknown encoding type."""
        p = EncodedPayload("data", "rot13", 1, 0)
        assert _decode_bytes(p) is None


class TestFacadeRoundTrip:
    """End-to-end: facade functions call helpers and produce correct results."""

    def test_extract_and_decode_base64(self) -> None:
        """Full round-trip: extract base64 from content and decode it."""
        original = "hello world test payload!"
        encoded = base64.b64encode(original.encode()).decode()
        content = f'secret = "{encoded}"'

        payloads = extract_encoded_strings(content)

        assert len(payloads) == 1
        decoded = decode_payload(payloads[0])
        assert decoded == original

    def test_extract_and_decode_hex(self) -> None:
        """Full round-trip: extract hex from content and decode it."""
        original = "hex round-trip content!"
        hex_str = original.encode().hex()
        content = f"data = bytes.fromhex('{hex_str}')"

        payloads = extract_encoded_strings(content)
        hex_payloads = [p for p in payloads if p.encoding_type == "hex"]

        assert len(hex_payloads) == 1
        decoded = decode_payload(hex_payloads[0])
        assert decoded == original

    def test_engine_imports_still_resolve(self) -> None:
        """engine.py's imports from decoder still work after the split."""
        from skill_scan.rules.engine import match_content  # noqa: F401

        # If this import succeeds, engine.py's
        # `from skill_scan.decoder import MAX_DECODE_DEPTH, decode_payload, extract_encoded_strings`
        # is working correctly.
        assert True


class TestFileSizeConstraints:
    """Both modules stay under the 250-line limit."""

    @pytest.mark.parametrize(
        "module_path",
        [
            "src/skill_scan/decoder.py",
            "src/skill_scan/_decoder_helpers.py",
        ],
    )
    def test_module_under_250_lines(self, module_path: str) -> None:
        """Each module file is at most 250 lines."""
        from pathlib import Path

        # Navigate from tests/ up to project root
        project_root = Path(__file__).resolve().parents[2]
        file_path = project_root / module_path
        line_count = len(file_path.read_text(encoding="utf-8").splitlines())
        assert line_count <= 250, f"{module_path} has {line_count} lines (limit: 250)"
