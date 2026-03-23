"""Dunder chain detector -- detect MRO walk and execution escape patterns.

Detects chained dunder attribute access patterns commonly used in Python
sandbox escapes, SSTI exploits, and CTF payloads. Two severity tiers:
HIGH for MRO-walk chains (2+ dunders from the walk set), CRITICAL when
execution-enabling dunders (__globals__, __builtins__, etc.) appear.

Node-level detector registered in _DETECTORS (ast_analyzer.py).

Chain-walking rules:
- Dangerous dunders (in MRO_WALK or EXEC_ESCAPE sets) are collected into
  the chain
- Non-dangerous dunders (e.g., __init__, __new__) are transparent -- the
  walker skips through them without adding to the chain (they serve as
  bridges in real exploit chains)
- Non-dunder attributes (e.g., some_method) break the chain
- ast.Subscript and ast.Call nodes are transparent (skipped through)

Dedup strategy: when a chain of 2+ dangerous Attribute nodes is found,
inner Attribute nodes are marked with ``_dunder_inner = True`` so that
subsequent calls for those inner nodes skip emission.
"""

from __future__ import annotations

import ast

from skill_scan.models import Finding, Severity

_RULE_ID = "EXEC-011"
_CATEGORY = "malicious-code"
_RECOMMENDATION = "Do not chain dunder attributes to walk the object graph; use explicit imports instead"

# Dunders used to walk the MRO / class hierarchy
MRO_WALK_DUNDERS: frozenset[str] = frozenset(
    {"__class__", "__base__", "__bases__", "__mro__", "__subclasses__"}
)

# Dunders that enable code execution once the MRO walk reaches them
EXEC_ESCAPE_DUNDERS: frozenset[str] = frozenset(
    {"__globals__", "__builtins__", "__import__", "__getattr__", "__code__"}
)

_ALL_DANGEROUS: frozenset[str] = MRO_WALK_DUNDERS | EXEC_ESCAPE_DUNDERS


def _is_dunder(name: str) -> bool:
    """Return True if *name* is a dunder (``__xxx__`` form)."""
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _collect_chain(node: ast.expr) -> tuple[list[str], list[ast.Attribute]]:
    """Walk inward from an ast.Attribute collecting consecutive dangerous dunders.

    Returns (chain_attrs, inner_dangerous_nodes) where inner_dangerous_nodes
    are the dangerous-dunder ast.Attribute objects found AFTER the starting
    node (should be skipped when visited later by ast.walk).

    Walking rules:
    - Dangerous-dunder Attribute: add to chain, record inner node, continue
    - Non-dangerous dunder Attribute: skip through (transparent bridge)
    - Non-dunder Attribute: break (chain ends)
    - ast.Subscript: skip to .value
    - ast.Call: skip to .func
    - Anything else: break
    """
    chain: list[str] = []
    inner_nodes: list[ast.Attribute] = []
    current: ast.expr = node
    is_first = True

    while True:
        if isinstance(current, ast.Attribute):
            attr = current.attr
            if attr in _ALL_DANGEROUS:
                chain.append(attr)
                if not is_first:
                    inner_nodes.append(current)
                is_first = False
                current = current.value
            elif _is_dunder(attr):
                # Non-dangerous dunder: transparent bridge (e.g., __init__)
                current = current.value
            else:
                # Non-dunder attr breaks the chain
                break
        elif isinstance(current, ast.Subscript):
            current = current.value
        elif isinstance(current, ast.Call):
            current = current.func
        else:
            break

    return chain, inner_nodes


def _detect_dunder_chain(
    node: ast.AST,
    file_path: str,
    *,
    alias_map: dict[str, str] | None = None,
) -> list[Finding]:
    """Detect chained dunder attribute access (MRO walk / execution escape).

    Returns EXEC-011 findings for chains of 2+ dangerous dunders.
    CRITICAL if any EXEC_ESCAPE_DUNDERS are present, HIGH otherwise.
    Marks inner chain nodes to prevent duplicate findings.
    """
    if not isinstance(node, ast.Attribute):
        return []

    # Skip nodes already claimed by a longer chain
    if getattr(node, "_dunder_inner", False):
        return []

    attr = node.attr
    if attr not in _ALL_DANGEROUS:
        return []

    chain, inner_nodes = _collect_chain(node)

    if len(chain) < 2:
        return []

    # Mark inner nodes so they don't emit when visited later
    for inner in inner_nodes:
        inner._dunder_inner = True  # type: ignore[attr-defined]

    return [_build_finding(chain, node, file_path)]


def _build_finding(chain: list[str], node: ast.Attribute, file_path: str) -> Finding:
    """Build an EXEC-011 finding from a validated dunder chain."""
    has_exec_escape = any(d in EXEC_ESCAPE_DUNDERS for d in chain)
    return Finding(
        rule_id=_RULE_ID,
        severity=Severity.CRITICAL if has_exec_escape else Severity.HIGH,
        category=_CATEGORY,
        file=file_path,
        line=getattr(node, "lineno", None),
        matched_text=".".join(reversed(chain)),
        description="MRO walk with execution escape detected"
        if has_exec_escape
        else "MRO walk chain detected",
        recommendation=_RECOMMENDATION,
    )
