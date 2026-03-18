"""AST detector for subprocess list-arg data exfiltration.

Detects subprocess.run/call/check_output/check_call/Popen where the
first positional arg is an ast.List containing string constants matching
network tool names (curl, wget, nc, ncat, netcat).

Pure function: no I/O, no logging, no side effects.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import get_call_name
from skill_scan.models import Finding, Severity

_SUBPROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.Popen",
    }
)

_NETWORK_TOOLS = frozenset({"curl", "wget", "nc", "ncat", "netcat"})

_CATEGORY = "data-exfiltration"
_RULE_ID = "EXFIL-001"
_RECOMMENDATION = "Remove or reject commands that silently POST data to external servers"


def _detect_subprocess_list_exfil(
    node: ast.AST, file_path: str, *, alias_map: dict[str, str] | None = None
) -> list[Finding]:
    """Detect subprocess calls with list args containing network tools.

    Catches patterns like:
      subprocess.run(['curl', '-d', data, url])
      subprocess.check_output(['wget', url])
      sp.Popen(['nc', host, port])  (aliased import)
    """
    if not isinstance(node, ast.Call):
        return []

    name = get_call_name(node, alias_map)
    if name not in _SUBPROCESS_CALLS:
        return []

    # Must have at least one positional arg that is a list
    if not node.args or not isinstance(node.args[0], ast.List):
        return []

    elements = node.args[0].elts
    if not elements:
        return []

    # First element must be a string constant matching a network tool
    first = elements[0]
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return []

    tool_name = first.value.split("/")[-1]  # handle /usr/bin/curl
    if tool_name not in _NETWORK_TOOLS:
        return []

    return [
        Finding(
            rule_id=_RULE_ID,
            severity=Severity.CRITICAL,
            category=_CATEGORY,
            file=file_path,
            line=node.lineno,
            matched_text=f"{name}(['{first.value}', ...])",
            description=f"Subprocess list-arg exfiltration -- {name}() with '{tool_name}' detected via AST",
            recommendation=_RECOMMENDATION,
        )
    ]
