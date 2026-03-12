"""URL and unicode-escape decoder internals.

Private module. All names are re-exported from decoder.py for backward
compatibility -- import from ``skill_scan.decoder``, not from here.

Extraction helpers find encoded payloads in source lines; decode helpers
convert them back to plain text. Both return ``str`` (not bytes).
"""

from __future__ import annotations

import re
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skill_scan.decoder import EncodedPayload

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# URL-encoded: 3+ consecutive %XX sequences.
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")

# Unicode escape: 3+ consecutive \uXXXX or \UXXXXXXXX sequences.
# Matches literal backslash-u in source text (not Python-interpreted escapes).
_UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}){3,}")


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _payloads_from_re(
    pattern: re.Pattern[str], encoding_type: str, line: str, line_num: int
) -> list[EncodedPayload]:
    """Extract EncodedPayload instances for all matches of *pattern* in *line*."""
    from skill_scan.decoder import EncodedPayload

    return [
        EncodedPayload(
            encoded_text=match.group(),
            encoding_type=encoding_type,
            line_num=line_num,
            start_offset=match.start(),
        )
        for match in pattern.finditer(line)
    ]


def _extract_url_encoded_from_line(line: str, line_num: int) -> list[EncodedPayload]:
    """Extract URL-encoded payloads (3+ consecutive %XX) from a single line."""
    return _payloads_from_re(_URL_ENCODED_RE, "url", line, line_num)


def _extract_unicode_escape_from_line(line: str, line_num: int) -> list[EncodedPayload]:
    r"""Extract unicode-escape payloads (3+ \uXXXX/\UXXXXXXXX) from a line."""
    return _payloads_from_re(_UNICODE_ESCAPE_RE, "unicode_escape", line, line_num)


# ---------------------------------------------------------------------------
# Decode helpers (str-returning, bypass _decode_bytes -> utf-8 path)
# ---------------------------------------------------------------------------


def _decode_url_encoded(text: str) -> str:
    """Decode a URL-encoded string to plain text.

    Uses ``urllib.parse.unquote`` (stdlib). Strips null bytes from the
    decoded output to prevent null-byte-interspersed evasion.

    Args:
        text: URL-encoded string (e.g. ``%65%76%61%6C%28%29``).

    Returns:
        Decoded plain text string with null bytes removed.
    """
    return urllib.parse.unquote(text).replace("\x00", "")


def _decode_unicode_escape(text: str) -> str:
    r"""Decode a unicode-escape string to plain text.

    Handles ``\uXXXX`` and ``\UXXXXXXXX`` sequences by encoding to
    raw bytes and decoding with ``unicode_escape``. Strips lone surrogate
    characters (U+D800-U+DFFF) from the decoded output to prevent
    surrogate-based evasion.

    Args:
        text: Unicode-escaped string (e.g. ``\u0065\u0076\u0061\u006C``).

    Returns:
        Decoded plain text string with surrogates removed.

    Raises:
        ValueError: If the escape sequence is malformed.
    """
    decoded = text.encode("raw_unicode_escape").decode("unicode_escape")
    return "".join(c for c in decoded if not (0xD800 <= ord(c) <= 0xDFFF))
