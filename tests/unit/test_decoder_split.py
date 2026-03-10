"""Tests for decoder.py / _decoder_helpers.py module split.

Verifies that the Facade Re-export Pattern preserves all import paths
and that both modules contain the expected names.
"""

from __future__ import annotations

import base64

from skill_scan.decoder import (
    decode_payload,
    extract_encoded_strings,
)


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
