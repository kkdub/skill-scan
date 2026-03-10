"""Decoder internals — regex patterns, extraction helpers, and decode functions.

Private module. All names are re-exported from decoder.py for backward
compatibility — import from ``skill_scan.decoder``, not from here.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skill_scan.decoder import EncodedPayload

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# Quantifiers derived from MIN_ENCODED_LENGTH so a single constant governs
# all thresholds.  We import the value lazily (see _min_len()) to avoid a
# circular import at module level.


def _min_len() -> int:
    from skill_scan.decoder import MIN_ENCODED_LENGTH

    return MIN_ENCODED_LENGTH


_L = _min_len()
_L_B64 = max(1, _L - 3)  # allow up to 3 '=' padding chars within MIN_ENCODED_LENGTH
_HB = _L // 2  # hex bytes needed (escape sequences)
_HF = _HB - 1  # repeat count for fromhex pattern (first pair is outside the group)

# Base64: standalone blocks or quoted strings of [A-Za-z0-9+/] with optional = padding.
# Regex threshold uses _L_B64 (lower) to catch padding-inclusive strings; the explicit
# len(text) >= MIN_ENCODED_LENGTH check in _extract_base64_from_line enforces the real minimum.
_BASE64_RE = re.compile(
    rf"""(?:["'])([A-Za-z0-9+/]{{{_L_B64},}}={{0,3}})(?:["'])"""
    rf"""|(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{{{_L_B64},}}={{0,3}})(?![A-Za-z0-9+/])""",
)

# bytes.fromhex('...') calls — allows optional spaces between hex byte pairs.
_HEX_FROMHEX_RE = re.compile(
    rf"""bytes\.fromhex\(\s*["']([0-9a-fA-F]{{2}}(?:[\s]?[0-9a-fA-F]{{2}}){{{_HF},}})["']\s*\)""",
)

# \xNN escape sequences (at least MIN//2 bytes = MIN hex chars).
_HEX_ESCAPE_RE = re.compile(
    rf"""((?:\\x[0-9a-fA-F]{{2}}){{{_HB},}})""",
)

# 0x-prefixed hex blocks (standalone, at least MIN_ENCODED_LENGTH hex digits after 0x).
_HEX_BLOCK_RE = re.compile(
    rf"""(?<![A-Za-z0-9])0x([0-9a-fA-F]{{{_L},}})(?![A-Za-z0-9])""",
)


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _extract_base64_from_line(line: str, line_num: int) -> list[EncodedPayload]:
    """Extract base64-encoded strings from a single line."""
    from skill_scan.decoder import EncodedPayload, MIN_ENCODED_LENGTH

    results: list[EncodedPayload] = []
    for match in _BASE64_RE.finditer(line):
        # Per-match data:image/ exclusion — check if this match is data URI payload.
        before = line[: match.start()]
        if re.search(r"data:image/[^;]*;base64,$", before, re.IGNORECASE):
            continue
        text = match.group(1) or match.group(2)
        if text and len(text) >= MIN_ENCODED_LENGTH:
            # Use group start (not match start) to point at the encoded text, not surrounding quotes.
            group_idx = 1 if match.group(1) is not None else 2
            results.append(
                EncodedPayload(
                    encoded_text=text,
                    encoding_type="base64",
                    line_num=line_num,
                    start_offset=match.start(group_idx),
                )
            )
    return results


def _extract_hex_from_line(line: str, line_num: int) -> list[EncodedPayload]:
    """Extract hex-encoded strings from a single line."""
    from skill_scan.decoder import EncodedPayload, MIN_ENCODED_LENGTH

    results: list[EncodedPayload] = []

    # bytes.fromhex('...') — strip spaces for length check, keep for decoding.
    for match in _HEX_FROMHEX_RE.finditer(line):
        text = match.group(1)
        if len(text.replace(" ", "")) >= MIN_ENCODED_LENGTH:
            results.append(
                EncodedPayload(
                    encoded_text=text,
                    encoding_type="hex",
                    line_num=line_num,
                    start_offset=match.start(),
                )
            )

    # \xNN escape sequences
    for match in _HEX_ESCAPE_RE.finditer(line):
        raw = match.group(1)
        hex_text = raw.replace("\\x", "")
        if len(hex_text) >= MIN_ENCODED_LENGTH:
            results.append(
                EncodedPayload(
                    encoded_text=hex_text,
                    encoding_type="hex",
                    line_num=line_num,
                    start_offset=match.start(),
                )
            )

    # 0x-prefixed hex blocks
    for match in _HEX_BLOCK_RE.finditer(line):
        text = match.group(1)
        if len(text) >= MIN_ENCODED_LENGTH:
            results.append(
                EncodedPayload(
                    encoded_text=text,
                    encoding_type="hex",
                    line_num=line_num,
                    start_offset=match.start(),
                )
            )

    return results


# ---------------------------------------------------------------------------
# Decode helpers
# ---------------------------------------------------------------------------


def _decode_bytes(payload: EncodedPayload) -> bytes | None:
    """Decode raw bytes from an encoded payload.

    Args:
        payload: The encoded payload to decode.

    Returns:
        Decoded bytes or None on failure.
    """
    if payload.encoding_type == "base64":
        return _decode_base64(payload.encoded_text)
    if payload.encoding_type == "hex":
        return _decode_hex(payload.encoded_text)
    return None


def _decode_base64(text: str) -> bytes | None:
    """Decode a base64-encoded string, returning None on failure.

    Strips whitespace and normalizes padding before decoding.

    Note: whitespace stripping is not exercised by the regex extraction path
    (_BASE64_RE excludes spaces from its charset), but it is reachable when
    callers construct EncodedPayload directly with pre-split or manually
    spaced strings.  It is kept for correctness on those call paths.
    """
    text = text.replace(" ", "").replace("\t", "")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        pass
    # Retry with normalized padding (handles missing/extra '=').
    stripped = text.rstrip("=")
    text = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _decode_hex(text: str) -> bytes | None:
    """Decode a hex-encoded string, returning None on failure."""
    try:
        return bytes.fromhex(text)
    except (ValueError, binascii.Error):
        return None
