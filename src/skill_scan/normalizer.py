"""Text normalization for evasion-resistant matching.

Strips invisible Unicode characters and canonicalizes whitespace so that
obfuscated content (e.g. e\u200bv\u200ba\u200bl) matches detection rules
written for the plain form (eval).
"""

from __future__ import annotations

import re

# Zero-width and invisible characters that can break up words to evade detection.
# U+200B  ZWSP (zero width space)
# U+200C  ZWNJ (zero width non-joiner)
# U+200D  ZWJ  (zero width joiner)
# U+2060  WJ   (word joiner)
# U+FEFF  BOM / ZWNBSP (byte order mark / zero width no-break space)
# U+00AD  Soft hyphen (invisible in most renderings)
_ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad]")

# Exotic whitespace characters that should be treated as a regular space.
# U+00A0        Non-breaking space
# U+2000-U+200A Various typographic spaces (en quad through hair space)
# U+202F        Narrow no-break space
# U+205F        Medium mathematical space
# U+3000        Ideographic space
_EXOTIC_SPACE_RE = re.compile(
    "[\u00a0\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000]"
)

# Two or more consecutive regular spaces (for collapsing after replacement).
_MULTI_SPACE_RE = re.compile(" {2,}")


def strip_zero_width(text: str) -> str:
    """Remove zero-width and invisible characters from *text*.

    Strips U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+2060 (WJ),
    U+FEFF (BOM/ZWNBSP) and U+00AD (soft hyphen).

    Args:
        text: Input string, possibly containing invisible characters.

    Returns:
        String with all zero-width / invisible characters removed.
    """
    return _ZERO_WIDTH_RE.sub("", text)


def canonicalize_whitespace(text: str) -> str:
    """Replace exotic whitespace with standard spaces and collapse runs.

    Converts non-breaking spaces, typographic spaces (U+2000-U+200A),
    narrow no-break space, medium mathematical space, and ideographic
    space into regular space (U+0020), then collapses consecutive spaces
    into one.

    Newlines and tabs are preserved because they carry structural meaning
    in source code and configuration files.

    Args:
        text: Input string with potentially exotic whitespace.

    Returns:
        String with normalized whitespace.
    """
    result = _EXOTIC_SPACE_RE.sub(" ", text)
    return _MULTI_SPACE_RE.sub(" ", result)


def normalize_text(text: str) -> str:
    """Apply full normalization pipeline to *text*.

    Strips zero-width characters then canonicalizes whitespace. This is
    the main entry point used by the matching engine.

    Newline characters are preserved so this function can safely be
    applied to multi-line content (e.g. for file-scope rule matching).

    Args:
        text: Input string to normalize.

    Returns:
        Normalized string.
    """
    return canonicalize_whitespace(strip_zero_width(text))
