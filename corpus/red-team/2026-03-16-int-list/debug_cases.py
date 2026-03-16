"""Debug specific surprising failures."""

from __future__ import annotations
import ast
from skill_scan._ast_split_join_helpers import (
    _collect_int_list_assigns,
    _resolve_comprehension_join,
    _resolve_join_call,
    _lookup_int_list,
)
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan._ast_split_detector import detect_split_evasion, _build_scope_map

_FILE = "test.py"


def debug_case(name: str, code: str):
    print(f"\n=== {name} ===")
    print(f"Code: {code!r}")
    tree = ast.parse(code)
    ilt = _collect_int_list_assigns(tree)
    st = build_symbol_table(tree)
    print(f"  int_list_table: {ilt}")
    print(f"  symbol_table: {st}")

    scope_map = _build_scope_map(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = getattr(node, 'func', None)
            if isinstance(func, ast.Attribute) and func.attr == 'join':
                scope = scope_map.get(id(node), "")
                print(f"  Found join call at line {getattr(node, 'lineno', '?')}, scope={scope!r}")
                result = _resolve_join_call(node, st, scope, {}, int_list_table=ilt)
                print(f"  _resolve_join_call result: {result!r}")

    findings = detect_split_evasion(tree, _FILE, {}, st, int_list_table=ilt)
    print(f"  Findings: {[(f.rule_id, f.matched_text) for f in findings]}")


# Bool case: True is an int subclass, value 1 -> chr(1) = SOH control char
# So codes = [True, 118, 97, 108] -> chr(1) + chr(118) + chr(97) + chr(108) = "\x01val"
# This is NOT "eval" -- it's correct behavior that no EXEC-002 is raised!
debug_case("bool_true", "codes = [True, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)")

# Large list: codes = [eval * 25] -> "eval" * 25 = "evaleval...eval"
# This SHOULD produce EXEC-002 since it contains "eval" -- but _check_dangerous does exact match
debug_case("large_list", "codes = " + repr([ord(c) for c in "eval" * 25]) + "\nx = ''.join(chr(c) for c in codes)")

# Filter: comp.ifs is non-empty -> _resolve_comprehension_join returns None
debug_case("filter_in_comp",
           "codes = [101, 118, 97, 108, 0]\nx = ''.join(chr(c) for c in codes if c > 0)")

# Cond expr in elt: elt is IfExp not Call -> _resolve_comprehension_chr returns None
debug_case("cond_expr_elt",
           "codes = [101, 118, 97, 108]\nx = ''.join(chr(c) if c > 0 else '' for c in codes)")
