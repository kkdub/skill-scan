"""AST-based Python code analyzer — detect unsafe patterns via syntax tree.

Pure module using stdlib ast. No I/O, no logging, no side effects.
Takes a Python source string and returns a list of Finding objects.

This is a facade module: it retains the public entry point (analyze_python)
and re-exports all names from _ast_detectors so that every existing import
path continues to work. The `x as x` form signals explicit re-export to
type checkers (PEP 484).
"""

from __future__ import annotations

import ast

from skill_scan.models import Finding, Severity


def analyze_python(content: str, file_path: str) -> list[Finding]:
    """Analyze Python source for unsafe patterns using AST.

    Parses with ast.parse() and walks the tree looking for dangerous patterns
    that regex might miss (e.g., string concatenation building dangerous names).
    Returns an INFO finding on SyntaxError/ValueError. May produce duplicates
    by (rule_id, line) — callers should deduplicate if needed
    (content_scanner._deduplicate handles this).
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return [
            Finding(
                rule_id="AST-PARSE",
                severity=Severity.INFO,
                category="analysis",
                file=file_path,
                line=None,
                matched_text="",
                description="AST analysis skipped due to parse error",
                recommendation="Verify file contains valid Python syntax",
            )
        ]

    findings: list[Finding] = []
    try:
        for node in ast.walk(tree):
            findings.extend(_detect_unsafe_calls(node, file_path))
            findings.extend(_detect_dynamic_imports(node, file_path))
            findings.extend(_detect_unsafe_deserialization(node, file_path))
            findings.extend(_detect_string_concat_evasion(node, file_path))
            findings.extend(_detect_dynamic_access(node, file_path))
    except RecursionError:
        findings.append(
            Finding(
                rule_id="AST-DEPTH",
                severity=Severity.INFO,
                category="analysis",
                file=file_path,
                line=None,
                matched_text="",
                description="AST analysis truncated due to excessive recursion depth",
                recommendation="Check file for adversarial nesting patterns",
            )
        )
    return findings


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
