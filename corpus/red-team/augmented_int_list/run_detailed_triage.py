"""Detailed triage: scan individual code snippets from each pattern."""
from __future__ import annotations

import ast
from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_join_helpers import _collect_int_list_assigns
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_FILE = "test.py"

def _detect(code: str, label: str) -> None:
    """Run detection and print results for a labeled snippet."""
    tree = ast.parse(code)
    st = build_symbol_table(tree)
    ilt = _collect_int_list_assigns(tree)
    findings = detect_split_evasion(tree, _FILE, {}, st, int_list_table=ilt)
    exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
    status = "DETECTED" if exec_findings else "EVADED"
    print(f"  {label}: {status} ({len(exec_findings)} findings)")
    if exec_findings:
        for f in exec_findings:
            print(f"    L{f.line}: {f.rule_id}")
    # Also show int_list_table for debugging
    print(f"    int_list_table: {ilt}")


if __name__ == "__main__":
    print("=== multiple_plusequals_chains patterns ===")

    _detect(
        "codes = [101]\ncodes += [118]\ncodes += [97]\ncodes += [108]\nx = ''.join(chr(c) for c in codes)",
        "Pattern 1: Long += chain"
    )

    _detect(
        "def chain_func():\n    c = [101]\n    c += [120]\n    c += [101]\n    c += [99]\n    x = ''.join(chr(i) for i in c)",
        "Pattern 2: += chain in function"
    )

    _detect(
        "codes2 = [101]\ncodes2 += (118, 97, 108)\nx2 = ''.join(chr(c) for c in codes2)",
        "Pattern 4: += with tuple RHS"
    )

    _detect(
        "def five_step():\n    data = []\n    data += [95]\n    data += [95]\n    data += [105]\n    data += [109]\n    data += [112]\n    data += [111]\n    data += [114]\n    data += [116]\n    data += [95]\n    data += [95]\n    x = ''.join(chr(c) for c in data)",
        "Pattern 5: __import__ via += chain"
    )

    print("\n=== edge_cases patterns ===")

    _detect(
        "class Evasion:\n    codes = [101, 118]\n    codes += [97, 108]\n    x = ''.join(chr(c) for c in codes)",
        "Pattern 4: class-scoped +="
    )

    _detect(
        "codes4 = [101, 118, 97, 108]\ncodes4 *= 1\nx4 = ''.join(chr(c) for c in codes4)",
        "Pattern 7: *= (non-Add op)"
    )

    print("\n=== mixed_mutation: should NOT detect ===")

    _detect(
        "codes3 = [101, 118]\ncodes3 += [97, 108]\ncodes3 = [104, 105]\nx3 = ''.join(chr(c) for c in codes3)",
        "Pattern 4: reassign after += (safe)"
    )

    _detect(
        "def shadow_after_mutation():\n    codes = [101, 118]\n    codes += [97, 108]\n    codes = 'hello'\n    x = ''.join(chr(c) for c in codes)",
        "Pattern 5: shadow with string"
    )

    print("\n=== extend_generator_arg (out of scope) ===")

    _detect(
        "codes = [101, 118]\ncodes.extend(x for x in [97, 108])\nx = ''.join(chr(c) for c in codes)",
        "Pattern 1: Generator arg (expect no crash)"
    )
