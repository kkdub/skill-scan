"""Inline import chain detector -- ``__import__('mod').dangerous()``.

Extracted from ``_ast_detectors.py`` to keep that file under 350 lines.
Detects patterns like ``__import__('os').system('cmd')`` and
``importlib.import_module('subprocess').call(['ls'])``, emitting
EXEC-002 CRITICAL.

The ``_INLINE_CHAIN_ATTRS`` set includes both the original dangerous
builtins (eval, exec, system, popen) and subprocess family names
(call, check_output, Popen, run, check_call).

``_IMPORT_CALL_NAMES`` is the whitelist of recognized import call names
shared with ``_ast_ref_tracker.py``.
"""

from __future__ import annotations

import ast

from skill_scan._ast_detectors import _make_finding
from skill_scan._ast_imports import get_call_name
from skill_scan.models import Finding, Severity

_IMPORT_CALL_NAMES = frozenset(
    {"__import__", "importlib.import_module", "builtins.__import__", "__builtins__.__import__"},
)

# Dangerous attrs for inline import chains (__import__('os').system())
# Includes original builtins + subprocess family
_INLINE_CHAIN_ATTRS = frozenset(
    {"eval", "exec", "system", "popen", "call", "check_output", "Popen", "run", "check_call"}
)


def _detect_inline_import_chain(
    node: ast.AST, file_path: str, *, alias_map: dict[str, str] | None = None
) -> list[Finding]:
    """Detect __import__('mod').dangerous() and importlib.import_module('mod').dangerous()."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return []
    inner = node.func.value
    if not isinstance(inner, ast.Call):
        return []
    attr = node.func.attr
    if attr not in _INLINE_CHAIN_ATTRS:
        return []
    inner_name = get_call_name(inner, alias_map)
    if inner_name not in _IMPORT_CALL_NAMES:
        return []
    arg0 = inner.args[0] if inner.args else None
    mod = str(arg0.value) if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) else "?"
    return [
        _make_finding(
            rule_id="EXEC-002",
            severity=Severity.CRITICAL,
            file=file_path,
            line=node.lineno,
            matched_text=f"{inner_name}('{mod}').{attr}(",
            description=f"Inline import chain -- {inner_name}('{mod}').{attr}() detected via AST",
        )
    ]
