"""AST detectors for ROT13 obfuscation patterns (OBFS-001).

Pure functions that detect ROT13 usage via:
  - codecs.encode/decode with 'rot_13' or 'rot13' encoding
  - codecs.getencoder/getdecoder/lookup/iterencode with ROT13
  - str.maketrans() with a ROT13 character pair

All findings use rule_id='OBFS-001', severity=HIGH, category='obfuscation'.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import get_call_name, try_resolve_string
from skill_scan.models import Finding, Severity

_RULE_ID = "OBFS-001"
_SEVERITY = Severity.HIGH
_CATEGORY = "obfuscation"
_RECOMMENDATION = "Remove ROT13 encoding; use plain text or a legitimate encoding scheme"

_ROT13_VARIANTS = frozenset({"rot_13", "rot13"})

# codecs functions that accept an encoding name as first positional arg
_CODEC_DIRECT = frozenset({"codecs.encode", "codecs.decode"})
# encoding is the first positional arg for these
_CODEC_INDIRECT = frozenset(
    {
        "codecs.getencoder",
        "codecs.getdecoder",
        "codecs.lookup",
    }
)
# iterencode/iterdecode take (iterator, encoding, ...) — encoding is arg[1]
_CODEC_ENCODING_ARG1 = frozenset({"codecs.iterencode"})


def is_rot13_pair(from_str: str, to_str: str) -> bool:
    """Check whether (from_str, to_str) forms a ROT13 substitution mapping.

    A valid ROT13 pair maps every letter in from_str to its ROT13 counterpart
    at the same position in to_str, and vice versa. Both strings must have the
    same length and, considering only alphabetic characters, must cover at
    least 26 distinct letters (a full alphabet) in each of from_str and to_str.
    """
    if len(from_str) != len(to_str) or len(from_str) < 26:
        return False
    if not _has_full_alphabet(from_str) or not _has_full_alphabet(to_str):
        return False
    return all(
        _rot13_char(fc) == tc
        for fc, tc in zip(from_str, to_str, strict=False)
        if fc.isalpha() and tc.isalpha()
    )


def _has_full_alphabet(s: str) -> bool:
    """Check that s contains at least 26 distinct alphabetic characters (case-insensitive)."""
    return len({ch.lower() for ch in s if ch.isalpha()}) >= 26


def _rot13_char(c: str) -> str:
    """Apply ROT13 to a single alphabetic character."""
    if "a" <= c <= "z":
        return chr((ord(c) - ord("a") + 13) % 26 + ord("a"))
    if "A" <= c <= "Z":
        return chr((ord(c) - ord("A") + 13) % 26 + ord("A"))
    return c


def _detect_rot13_codec(
    node: ast.AST, file_path: str, *, alias_map: dict[str, str] | None = None
) -> list[Finding]:
    """Detect codecs.encode/decode/getencoder/getdecoder/lookup/iterencode with ROT13."""
    if not isinstance(node, ast.Call):
        return []

    name = get_call_name(node, alias_map)
    encoding = _extract_codec_encoding(node, name)

    if encoding is not None and encoding.lower() in _ROT13_VARIANTS:
        return [_make_rot13_finding(file_path, node.lineno, name, encoding)]

    return []


def _extract_codec_encoding(node: ast.Call, name: str) -> str | None:
    """Extract the encoding argument from a codecs call, or None if not applicable."""
    if name in _CODEC_DIRECT:
        return _extract_direct_encoding(node)
    if name in _CODEC_ENCODING_ARG1 and len(node.args) >= 2:
        return try_resolve_string(node.args[1])
    if name in _CODEC_INDIRECT and node.args:
        return try_resolve_string(node.args[0])
    return None


def _extract_direct_encoding(node: ast.Call) -> str | None:
    """Extract encoding from codecs.encode/decode (2nd positional or keyword)."""
    if len(node.args) >= 2:
        resolved = try_resolve_string(node.args[1])
        if resolved is not None:
            return resolved
    for kw in node.keywords:
        if kw.arg == "encoding":
            return try_resolve_string(kw.value)
    return None


def _detect_rot13_maketrans(
    node: ast.AST, file_path: str, *, alias_map: dict[str, str] | None = None
) -> list[Finding]:
    """Detect str.maketrans() with a ROT13 character mapping pair."""
    if not isinstance(node, ast.Call):
        return []

    # Match str.maketrans(from_str, to_str) -- exactly 2 positional args
    func = node.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "maketrans"
        and isinstance(func.value, ast.Name)
        and func.value.id == "str"
    ):
        return []

    if len(node.args) != 2:
        return []

    from_str = try_resolve_string(node.args[0])
    to_str = try_resolve_string(node.args[1])

    if from_str is None or to_str is None:
        return []

    if is_rot13_pair(from_str, to_str):
        return [
            Finding(
                rule_id=_RULE_ID,
                severity=_SEVERITY,
                category=_CATEGORY,
                file=file_path,
                line=node.lineno,
                matched_text="str.maketrans(ROT13 pair)",
                description="ROT13 obfuscation -- str.maketrans() with ROT13 character mapping",
                recommendation=_RECOMMENDATION,
            )
        ]

    return []


def _make_rot13_finding(file_path: str, line: int, call_name: str, encoding: str) -> Finding:
    """Build a Finding for ROT13 codec usage."""
    return Finding(
        rule_id=_RULE_ID,
        severity=_SEVERITY,
        category=_CATEGORY,
        file=file_path,
        line=line,
        matched_text=f"{call_name}(..., '{encoding}')",
        description=f"ROT13 obfuscation -- {call_name}() with '{encoding}' encoding detected via AST",
        recommendation=_RECOMMENDATION,
    )
