"""AST-based Python code analyzer -- detect unsafe patterns via syntax tree.

Pure module using stdlib ast. No I/O, no logging, no side effects.
Takes a Python source string and returns a list of Finding objects.

This is a facade module: it retains the public entry point (analyze_python)
and re-exports all names from _ast_detectors so that every existing import
path continues to work. The ``x as x`` form signals explicit re-export to
type checkers (PEP 484).
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import build_alias_map
from skill_scan.models import Finding, Severity


def analyze_python(content: str, file_path: str) -> list[Finding]:
    """Analyze Python source for unsafe patterns using AST.

    Parses with ast.parse() and walks the tree looking for dangerous patterns
    that regex might miss (e.g., string concatenation building dangerous names).
    Returns AST-PARSE INFO on parse error, AST-DEPTH INFO on recursion during
    walk. May produce duplicates by (rule_id, line) -- callers should deduplicate
    (content_scanner._deduplicate handles this).
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return [_parse_error_finding(file_path)]

    alias_map = build_alias_map(tree)
    findings: list[Finding] = []
    try:
        for node in ast.walk(tree):
            for detector in _DETECTORS:
                findings.extend(detector(node, file_path, alias_map=alias_map))
    except RecursionError:
        findings.append(_depth_error_finding(file_path))
    return findings


def _parse_error_finding(file_path: str) -> Finding:
    return Finding(
        rule_id="AST-PARSE",
        severity=Severity.INFO,
        category="analysis",
        file=file_path,
        line=None,
        matched_text="",
        description="AST analysis skipped due to parse error",
        recommendation="Verify file contains valid Python syntax",
    )


def _depth_error_finding(file_path: str) -> Finding:
    return Finding(
        rule_id="AST-DEPTH",
        severity=Severity.INFO,
        category="analysis",
        file=file_path,
        line=None,
        matched_text="",
        description="AST analysis truncated due to excessive recursion depth",
        recommendation="Check file for adversarial nesting patterns",
    )


# re-exports at BOTTOM -- backward-compat for all consumers (Facade Re-export Pattern)
from skill_scan._ast_detectors import (  # noqa: E402
    _CATEGORY as _CATEGORY,
    _DANGEROUS_NAMES as _DANGEROUS_NAMES,
    _RECOMMENDATIONS as _RECOMMENDATIONS,
    _UNSAFE_DESER_CALLS as _UNSAFE_DESER_CALLS,
    _UNSAFE_EXEC_CALLS as _UNSAFE_EXEC_CALLS,
    _detect_dynamic_access as _detect_dynamic_access,
    _detect_dynamic_imports as _detect_dynamic_imports,
    _detect_string_concat_evasion as _detect_string_concat_evasion,
    _detect_unsafe_calls as _detect_unsafe_calls,
    _detect_unsafe_deserialization as _detect_unsafe_deserialization,
    _make_finding as _make_finding,
)
from skill_scan._ast_rot13 import (  # noqa: E402
    _CODEC_DIRECT as _CODEC_DIRECT,
    _CODEC_INDIRECT as _CODEC_INDIRECT,
    _detect_rot13_codec as _detect_rot13_codec,
    _detect_rot13_maketrans as _detect_rot13_maketrans,
    is_rot13_pair as is_rot13_pair,
)

_DETECTORS = (
    _detect_unsafe_calls,
    _detect_dynamic_imports,
    _detect_unsafe_deserialization,
    _detect_string_concat_evasion,
    _detect_dynamic_access,
    _detect_rot13_codec,
    _detect_rot13_maketrans,
)
