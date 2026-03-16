"""AST split match -- dangerous name matching for split detector results.

Matches resolved strings against dangerous names and bridges to the decoder
for base64/hex/url encoded payloads.
"""

from __future__ import annotations

import ast
import re

from skill_scan._ast_detectors import _DANGEROUS_NAMES, _make_finding
from skill_scan.decoder import decode_payload, extract_encoded_strings
from skill_scan.models import Finding, Severity

# EXEC-006 names (dynamic import/indirection) vs EXEC-002 (code execution)
_DYNAMIC_IMPORT_NAMES = frozenset({"__import__", "getattr"})
_EXEC_NAMES = _DANGEROUS_NAMES - _DYNAMIC_IMPORT_NAMES
_NAME_RULE: dict[str, tuple[str, Severity, str]] = {
    **{n: ("EXEC-002", Severity.CRITICAL, "String splitting evasion") for n in _EXEC_NAMES},
    **{n: ("EXEC-006", Severity.HIGH, "Dynamic import evasion") for n in _DYNAMIC_IMPORT_NAMES},
}


def _check_dangerous(
    resolved: str,
    file_path: str,
    node: ast.AST,
    *,
    label: str = "split variable",
) -> Finding | None:
    """Return a Finding for a dangerous assembled name, or None if safe."""
    entry = _NAME_RULE.get(resolved)
    if entry is not None:
        rule_id, severity, desc_prefix = entry
        if label == "call-return":
            desc_prefix = "Call-return evasion"
        return _make_finding(
            rule_id=rule_id,
            severity=severity,
            file=file_path,
            line=getattr(node, "lineno", None),
            matched_text=f"{label} evasion building '{resolved}'",
            description=f"{desc_prefix} -- {label} resolves to '{resolved}' via AST",
        )
    # Bridge to decoder for base64/hex/url encoded payloads
    for payload in extract_encoded_strings(resolved):
        decoded = decode_payload(payload)
        if decoded is None:
            continue
        for name in _DANGEROUS_NAMES:
            if re.search(rf"\b{re.escape(name)}\b", decoded):
                return _make_finding(
                    rule_id="EXEC-002",
                    severity=Severity.CRITICAL,
                    file=file_path,
                    line=getattr(node, "lineno", None),
                    matched_text=f"split encoded evasion: decoded '{name}'",
                    description=f"Encoded payload decoded to dangerous name '{name}' via AST",
                )
    return None
