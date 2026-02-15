#!/usr/bin/env python3
"""AST detection of infrastructure (I/O) signals for architecture smell analysis."""

from __future__ import annotations

import ast

from .infra_calls import call_signals
from .models import InfraSignal


def infra_signals_for_node(node: ast.AST) -> list[InfraSignal]:
    """Return infrastructure signals for a single AST node, or empty list."""
    for checker in (
        _signals_call,
        _signals_subscript_environ,
        _signals_attr_environ,
    ):
        sigs = checker(node)
        if sigs:
            return sigs
    return []


def _signals_call(node: ast.AST) -> list[InfraSignal]:
    """Return signals if node is a Call; else empty list."""
    if isinstance(node, ast.Call):
        return call_signals(node)
    return []


def _signals_subscript_environ(node: ast.AST) -> list[InfraSignal]:
    """Return signal for os.environ[]; else empty list."""
    if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Attribute):
        return []
    if node.value.attr != "environ":
        return []
    if not isinstance(node.value.value, ast.Name) or node.value.value.id != "os":
        return []
    return [InfraSignal("env", "os.environ[]", node.lineno)]


def _signals_attr_environ(node: ast.AST) -> list[InfraSignal]:
    """Return signal for os.environ; else empty list."""
    if not isinstance(node, ast.Attribute) or node.attr != "environ":
        return []
    if not isinstance(node.value, ast.Name) or node.value.id != "os":
        return []
    return [InfraSignal("env", "os.environ", node.lineno)]
