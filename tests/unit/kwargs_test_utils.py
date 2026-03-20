"""Shared test helpers for kwargs unpacking detector tests."""

from __future__ import annotations

import ast
import textwrap

from skill_scan._ast_kwargs_detector import detect_kwargs_unpacking
from skill_scan._ast_imports import build_alias_map
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_FILE = "test.py"


def detect(code: str) -> list[Finding]:
    """Parse code, build symbol table, run kwargs detector."""
    tree = ast.parse(textwrap.dedent(code))
    alias_map = build_alias_map(tree)
    st = build_symbol_table(tree)
    return detect_kwargs_unpacking(tree, _FILE, alias_map, st)


def detect_full(code: str) -> list[Finding]:
    """Run full analyze_python pipeline."""
    return analyze_python(textwrap.dedent(code), _FILE)
