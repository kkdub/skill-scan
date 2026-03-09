"""Tests for decoder — base64/hex extraction and decoding."""

from __future__ import annotations

import base64

from skill_scan.decoder import (
    MAX_DECODED_SIZE,
    MIN_ENCODED_LENGTH,
    EncodedPayload,
    decode_payload,
    extract_encoded_strings,
)


def _make_payload(text: str, encoding: str) -> EncodedPayload:
    """Construct an EncodedPayload with default line/offset for unit tests."""
    return EncodedPayload(encoded_text=text, encoding_type=encoding, line_num=1, start_offset=0)


class TestExtractBase64:
    """Base64 string extraction from content."""

    def test_quoted_base64_string(self) -> None:
        """Extracts base64 strings from quoted contexts."""
        encoded = base64.b64encode(b"hello world, this is a test").decode()
        content = f'secret = "{encoded}"'

        payloads = extract_encoded_strings(content)

        assert len(payloads) == 1
        assert payloads[0].encoded_text == encoded
        assert payloads[0].encoding_type == "base64"
        assert payloads[0].line_num == 1

    def test_standalone_base64_block(self) -> None:
        """Extracts standalone base64 blocks not in quotes."""
        encoded = base64.b64encode(b"standalone payload data here").decode()
        content = f"data = {encoded}"

        payloads = extract_encoded_strings(content)

        assert len(payloads) >= 1
        b64_payloads = [p for p in payloads if p.encoding_type == "base64"]
        assert any(p.encoded_text == encoded for p in b64_payloads)

    def test_min_length_filtering(self) -> None:
        """Strings shorter than MIN_ENCODED_LENGTH are not extracted."""
        short = base64.b64encode(b"hi").decode()  # Very short
        assert len(short) < MIN_ENCODED_LENGTH
        content = f'x = "{short}"'

        payloads = extract_encoded_strings(content)

        assert len(payloads) == 0

    def test_data_image_uri_excluded(self) -> None:
        """data:image/ URIs are not extracted as base64."""
        encoded = base64.b64encode(b"this is fake image data!!").decode()
        content = f'img = "data:image/png;base64,{encoded}"'

        payloads = extract_encoded_strings(content)

        assert len(payloads) == 0

    def test_multiline_content(self) -> None:
        """Extracts base64 from multiple lines with correct line numbers."""
        enc1 = base64.b64encode(b"payload on line one here").decode()
        enc2 = base64.b64encode(b"payload on line three ok").decode()
        content = f'a = "{enc1}"\nsome code\nb = "{enc2}"'

        payloads = extract_encoded_strings(content)

        assert len(payloads) == 2
        assert payloads[0].line_num == 1
        assert payloads[1].line_num == 3


class TestExtractHex:
    """Hex string extraction from content."""

    def test_bytes_fromhex_call(self) -> None:
        """Extracts hex from bytes.fromhex('...') calls."""
        hex_str = b"hello world, test data!".hex()
        content = f"data = bytes.fromhex('{hex_str}')"

        payloads = extract_encoded_strings(content)
        hex_payloads = [p for p in payloads if p.encoding_type == "hex"]

        assert len(hex_payloads) == 1
        assert hex_payloads[0].encoded_text == hex_str

    def test_hex_escape_sequences(self) -> None:
        r"""Extracts hex from \xNN escape sequences."""
        # 12 bytes = 24 hex chars (meets minimum)
        hex_escapes = "".join(f"\\x{b:02x}" for b in b"hello world!")
        content = f'data = b"{hex_escapes}"'

        payloads = extract_encoded_strings(content)

        assert len(payloads) == 1
        assert payloads[0].encoding_type == "hex"

    def test_hex_block_0x_prefix(self) -> None:
        """Extracts 0x-prefixed hex blocks."""
        hex_str = b"this is a test payload!!".hex()
        content = f"value = 0x{hex_str}"

        payloads = extract_encoded_strings(content)
        hex_payloads = [p for p in payloads if p.encoding_type == "hex"]

        assert len(hex_payloads) == 1
        assert hex_payloads[0].encoded_text == hex_str

    def test_short_hex_not_extracted(self) -> None:
        """Hex strings shorter than MIN_ENCODED_LENGTH are skipped."""
        short_hex = b"hi".hex()  # 4 chars
        content = f"bytes.fromhex('{short_hex}')"

        payloads = extract_encoded_strings(content)

        assert len(payloads) == 0


class TestDecodePayload:
    """Decoding of extracted payloads."""

    def test_decode_valid_base64(self) -> None:
        """Decodes a valid base64 payload to UTF-8 string."""
        original = "hello world, decoded text"
        encoded = base64.b64encode(original.encode()).decode()
        payload = _make_payload(encoded, "base64")

        result = decode_payload(payload)

        assert result == original

    def test_decode_valid_hex(self) -> None:
        """Decodes a valid hex payload to UTF-8 string."""
        original = "decoded hex content here"
        hex_text = original.encode().hex()
        payload = _make_payload(hex_text, "hex")

        result = decode_payload(payload)

        assert result == original

    def test_invalid_base64_returns_none(self) -> None:
        """Invalid base64 returns None without raising."""
        payload = _make_payload("!!!not-valid-base64!!!??", "base64")

        result = decode_payload(payload)

        assert result is None

    def test_invalid_hex_returns_none(self) -> None:
        """Invalid hex returns None without raising."""
        payload = _make_payload("gghhiijjkkllmmnnooppqqrr", "hex")

        result = decode_payload(payload)

        assert result is None

    def test_non_utf8_bytes_returns_none(self) -> None:
        """Binary data that is not valid UTF-8 returns None."""
        binary_data = bytes(range(128, 160))  # Invalid UTF-8
        encoded = base64.b64encode(binary_data).decode()
        payload = _make_payload(encoded, "base64")

        result = decode_payload(payload)

        assert result is None

    def test_oversized_payload_returns_none(self) -> None:
        """Payloads exceeding MAX_DECODED_SIZE return None."""
        big_data = "A" * (MAX_DECODED_SIZE + 1)
        encoded = base64.b64encode(big_data.encode()).decode()
        payload = _make_payload(encoded, "base64")

        result = decode_payload(payload)

        assert result is None

    def test_max_depth_exceeded_returns_none(self) -> None:
        """Exceeding MAX_DECODE_DEPTH returns None."""
        encoded = base64.b64encode(b"test depth limiting ok").decode()
        payload = _make_payload(encoded, "base64")

        result = decode_payload(payload, depth=3)

        assert result is None

    def test_unknown_encoding_type_returns_none(self) -> None:
        """Unknown encoding type returns None."""
        payload = _make_payload("some text here for testing", "rot13")

        result = decode_payload(payload)

        assert result is None


class TestEncodedPayloadModel:
    """EncodedPayload dataclass behavior."""

    def test_frozen_immutable(self) -> None:
        """EncodedPayload is frozen and cannot be mutated."""
        payload = EncodedPayload("test", "base64", 1, 0)
        raised = True
        try:
            payload.encoded_text = "modified"  # type: ignore[misc]
            raised = False
        except AttributeError:
            pass
        assert raised
