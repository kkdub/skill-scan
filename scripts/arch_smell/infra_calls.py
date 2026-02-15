#!/usr/bin/env python3
"""Call-node detection for infrastructure signals (open, print, datetime, etc.)."""

from __future__ import annotations

import ast

from .constants import INFRA_CALLS
from .infra_patterns import get_object_name, is_http_client, is_infra_object
from .models import InfraSignal


def call_signals(node: ast.Call) -> list[InfraSignal]:
    """Return infrastructure signals for a Call node."""
    line = node.lineno
    if isinstance(node.func, ast.Name):
        sigs = _call_name_open(node) or _call_name_print(node)
        return sigs if sigs else []
    if not isinstance(node.func, ast.Attribute):
        return []
    attr = node.func.attr
    val = node.func.value
    sigs = (
        _call_datetime_attr(attr, val, line)
        or _call_time_attr(attr, val, line)
        or _call_subprocess_attr(attr, val, line)
    )
    return sigs if sigs else _method_call_signals(attr, val, line)


def _call_name_open(node: ast.Call) -> list[InfraSignal]:
    if isinstance(node.func, ast.Name) and node.func.id == "open":
        return [InfraSignal("filesystem", "open()", node.lineno)]
    return []


def _call_name_print(node: ast.Call) -> list[InfraSignal]:
    if isinstance(node.func, ast.Name) and node.func.id == "print":
        return [InfraSignal("logging", "print()", node.lineno)]
    return []


def _call_datetime_attr(attr: str, val: ast.AST, line: int) -> list[InfraSignal]:
    if attr not in ("now", "utcnow", "today"):
        return []
    if isinstance(val, ast.Name) and val.id == "datetime":
        return [InfraSignal("time", f"datetime.{attr}()", line)]
    if isinstance(val, ast.Attribute) and val.attr == "datetime":
        return [InfraSignal("time", f"datetime.{attr}()", line)]
    return []


def _call_time_attr(attr: str, val: ast.AST, line: int) -> list[InfraSignal]:
    if attr not in ("time", "monotonic", "perf_counter", "sleep"):
        return []
    if isinstance(val, ast.Name) and val.id == "time":
        return [InfraSignal("time", f"time.{attr}()", line)]
    return []


def _call_subprocess_attr(attr: str, val: ast.AST, line: int) -> list[InfraSignal]:
    if attr not in ("run", "call", "check_call", "check_output", "Popen"):
        return []
    if isinstance(val, ast.Name) and val.id == "subprocess":
        return [InfraSignal("subprocess", f"subprocess.{attr}()", line)]
    return []


def _method_call_signals(method: str, value: ast.AST, line: int) -> list[InfraSignal]:
    """Return 0 or 1 InfraSignal for a method call."""
    obj_name = get_object_name(value)
    if method == "get":
        if is_http_client(obj_name):
            return [InfraSignal("http", f"{obj_name}.get()", line)]
        if is_infra_object(obj_name, "env"):
            return [InfraSignal("env", f"{obj_name}.get()", line)]
        return []
    for category, methods in INFRA_CALLS.items():
        if method not in methods:
            continue
        if is_infra_object(obj_name, category):
            return [InfraSignal(category, f"{obj_name}.{method}()", line)]
    return []
