#!/usr/bin/env python3
"""Object-name pattern matching for infrastructure signal detection."""

from __future__ import annotations

import ast
from collections.abc import Callable

from .constants import INFRA_OBJECTS


def get_object_name(node: ast.AST) -> str:
    """Extract object name from AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
    return ""


def is_http_client(obj_name: str) -> bool:
    """True if object name indicates an HTTP client (not a dict)."""
    if not obj_name:
        return False
    obj_lower = obj_name.lower()
    dict_patterns = (
        "config",
        "data",
        "result",
        "response",
        "params",
        "headers",
        "json",
        "body",
    )
    if any(p in obj_lower for p in dict_patterns):
        return False
    http_patterns = ("client", "http", "requests", "httpx", "aiohttp", "session")
    return any(p in obj_lower for p in http_patterns)


def is_infra_object(obj_name: str, category: str) -> bool:
    """True if object name indicates infrastructure context for the category."""
    if not obj_name:
        return False
    obj_lower = obj_name.lower()
    if _matches_known(obj_lower, category):
        return True
    return _matches_category(obj_lower, category)


def _matches_known(obj_lower: str, category: str) -> bool:
    if category not in INFRA_OBJECTS:
        return False
    for pattern in INFRA_OBJECTS[category]:
        if pattern.lower() in obj_lower or obj_lower in pattern.lower():
            return True
    return False


def _matches_category(obj_lower: str, category: str) -> bool:
    handler = _CATEGORY_PATTERNS.get(category)
    if handler is None:
        return False
    return handler(obj_lower)


def _db(obj_lower: str) -> bool:
    return any(p in obj_lower for p in ("session", "db", "conn", "cursor", "engine"))


def _http(obj_lower: str) -> bool:
    return any(p in obj_lower for p in ("client", "http", "request", "response"))


def _filesystem(obj_lower: str) -> bool:
    return any(p in obj_lower for p in ("path", "file", "dir"))


def _env(obj_lower: str) -> bool:
    return "os" in obj_lower or "env" in obj_lower


def _logging(obj_lower: str) -> bool:
    return any(p in obj_lower for p in ("log", "logger", "_log", "_logger"))


def _time(obj_lower: str) -> bool:
    return any(p in obj_lower for p in ("datetime", "time", "clock"))


def _random(obj_lower: str) -> bool:
    return any(p in obj_lower for p in ("random", "rng", "secrets"))


def _subprocess(obj_lower: str) -> bool:
    return any(p in obj_lower for p in ("subprocess", "process", "proc", "popen"))


_CATEGORY_PATTERNS: dict[str, Callable[[str], bool]] = {
    "db": _db,
    "http": _http,
    "filesystem": _filesystem,
    "env": _env,
    "logging": _logging,
    "time": _time,
    "random": _random,
    "subprocess": _subprocess,
}
