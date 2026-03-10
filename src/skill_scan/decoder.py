"""Decoder module — extract and decode encoded payloads.

Pure module, no I/O. Finds base64 and hex-encoded strings in content
and attempts to decode them. Used by the scanner to detect obfuscated
payloads that may contain malicious commands.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- Constants ---

MIN_ENCODED_LENGTH = 20
"""Minimum length for an encoded string to be extracted (avoids false positives)."""

MAX_DECODED_SIZE = 100_000
"""Maximum decoded payload size in bytes (100KB limit per payload)."""

MAX_DECODE_DEPTH = 2
"""Maximum recursion depth for nested encoding detection."""

# --- Data model ---


@dataclass(slots=True, frozen=True)
class EncodedPayload:
    """A single encoded string found in source content."""

    encoded_text: str
    encoding_type: str  # 'base64' | 'hex'
    line_num: int
    start_offset: int


# Re-exports from _decoder_helpers (backward-compat).
# Every name that previously lived in this module is re-exported so that
# existing callers (from skill_scan.decoder import _BASE64_RE, ...) still work.
# The "x as x" form signals explicit re-export to type checkers (PEP 484).
#
# NOTE: must come after the constants and EncodedPayload above because
# _decoder_helpers.py reads MIN_ENCODED_LENGTH from this module at import time.
from skill_scan._decoder_helpers import (  # noqa: E402
    _BASE64_RE as _BASE64_RE,
    _HB as _HB,
    _HEX_BLOCK_RE as _HEX_BLOCK_RE,
    _HEX_ESCAPE_RE as _HEX_ESCAPE_RE,
    _HEX_FROMHEX_RE as _HEX_FROMHEX_RE,
    _HF as _HF,
    _L as _L,
    _L_B64 as _L_B64,
    _decode_base64 as _decode_base64,
    _decode_bytes as _decode_bytes,
    _decode_hex as _decode_hex,
    _extract_base64_from_line as _extract_base64_from_line,
    _extract_hex_from_line as _extract_hex_from_line,
)

# --- Extraction ---


def extract_encoded_strings(content: str) -> list[EncodedPayload]:
    """Find base64 and hex-encoded strings in *content*.

    Scans each line for patterns that look like encoded payloads.
    Strings shorter than MIN_ENCODED_LENGTH are skipped.
    data:image/ URIs are excluded from base64 results.

    Args:
        content: Source file content to scan.

    Returns:
        List of EncodedPayload instances found in the content.
    """

    payloads: list[EncodedPayload] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        payloads.extend(_extract_base64_from_line(line, line_num))
        payloads.extend(_extract_hex_from_line(line, line_num))
    return payloads


# --- Decoding ---


def decode_payload(payload: EncodedPayload, *, depth: int = 0) -> str | None:
    """Attempt to decode an encoded payload.

    Returns the decoded UTF-8 string, or None if decoding fails
    (invalid encoding, non-UTF-8 result, or exceeds size limits).

    Args:
        payload: The encoded payload to decode.
        depth: Current recursion depth (for nested encodings).

    Returns:
        Decoded string or None on failure.
    """

    if depth >= MAX_DECODE_DEPTH:
        return None

    # Pre-decode size estimate — reject oversized payloads before allocation.
    ratio = 0.75 if payload.encoding_type == "base64" else 0.5
    if int(len(payload.encoded_text) * ratio) > MAX_DECODED_SIZE:
        return None

    raw_bytes = _decode_bytes(payload)
    if raw_bytes is None:
        return None

    if len(raw_bytes) > MAX_DECODED_SIZE:
        return None

    try:
        decoded = raw_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None

    return decoded
