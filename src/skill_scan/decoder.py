"""Decoder module — extract and decode encoded payloads.

Pure module, no I/O. Finds base64 and hex-encoded strings in content
and attempts to decode them. Used by the scanner to detect obfuscated
payloads that may contain malicious commands.
"""

from __future__ import annotations

import base64
import binascii
import re
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


# --- Regex patterns ---
# Quantifiers derived from MIN_ENCODED_LENGTH so a single constant governs all thresholds.
# _BASE64_RE / _HEX_BLOCK_RE: match >= MIN_ENCODED_LENGTH characters.
# _HEX_ESCAPE_RE: each \xNN encodes 1 byte (2 hex chars), so MIN//2 sequences needed.
# _HEX_FROMHEX_RE: first pair is outside the repeat group, so repeat count is MIN//2 - 1.
_L = MIN_ENCODED_LENGTH  # shorthand for f-string readability
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


def _extract_base64_from_line(line: str, line_num: int) -> list[EncodedPayload]:
    """Extract base64-encoded strings from a single line."""
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
