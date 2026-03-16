"""Refined analysis: separate in-scope (R-EFF002) from out-of-scope evasions.

R-EFF002 claims: ''.join(chr(c) for c in codes) with tracked int-list resolves
correctly -- threshold: 0% false-negative rate on tracked int-list variables
used in chr comprehensions.

"Tracked int-list" means: _collect_int_list_assigns successfully adds it to
the int_list_table. Evasions that prevent tracking are a different gap (the
pre-pass doesn't see it) vs the resolution failing on a tracked variable.
"""

from __future__ import annotations

import ast
from skill_scan._ast_split_join_helpers import _collect_int_list_assigns
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan.ast_analyzer import analyze_python

_FILE = "test.py"

# Cases that are in-scope for R-EFF002: the int_list_table DOES track the var,
# and the comprehension pattern is exactly chr(c) for c in tracked_var
IN_SCOPE_CASES = [
    # Conditional: _collect_int_list_assigns does NOT recurse into if/for/while/with/try
    ("conditional_if",
     "if True:\n    codes = [101, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"),
    ("conditional_for",
     "for _ in range(1):\n    codes = [101, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"),
    ("conditional_try",
     "try:\n    codes = [101, 118, 97, 108]\nexcept Exception:\n    pass\nx = ''.join(chr(c) for c in codes)"),
    ("conditional_while",
     "while True:\n    codes = [101, 118, 97, 108]\n    break\nx = ''.join(chr(c) for c in codes)"),
    ("conditional_with",
     "import contextlib\nwith contextlib.nullcontext():\n    codes = [101, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"),
    ("conditional_else",
     "if False:\n    codes = [104, 101, 108, 108, 111]\nelse:\n    codes = [101, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"),
    ("conditional_if_in_func",
     "def f():\n    if True:\n        codes = [101, 118, 97, 108]\n    x = ''.join(chr(c) for c in codes)"),

    # Deep nesting: _collect_int_list_assigns only goes 1 level deep
    ("nested_func_in_func",
     "def outer():\n    def inner():\n        codes = [101, 118, 97, 108]\n        x = ''.join(chr(c) for c in codes)"),
    ("triple_nested",
     "def a():\n    def b():\n        def c():\n            codes = [101, 118, 97, 108]\n            x = ''.join(chr(c) for c in codes)"),
    ("class_in_func",
     "def f():\n    class C:\n        codes = [101, 118, 97, 108]\n        x = ''.join(chr(c) for c in codes)"),

    # Bool as int: True/False ARE int subclass, so they pass isinstance(v, int)
    ("bool_true_in_list",
     "codes = [True, 118, 97, 108]\nx = ''.join(chr(c) for c in codes)"),

    # Hex/octal/binary: Python AST folds these to plain int constants
    ("hex_literals",
     "codes = [0x65, 0x76, 0x61, 0x6c]\nx = ''.join(chr(c) for c in codes)"),
    ("octal_literals",
     "codes = [0o145, 0o166, 0o141, 0o154]\nx = ''.join(chr(c) for c in codes)"),
    ("binary_literals",
     "codes = [0b1100101, 0b1110110, 0b1100001, 0b1101100]\nx = ''.join(chr(c) for c in codes)"),

    # ListComp form (already tested but confirming)
    ("listcomp_form",
     "codes = [101, 118, 97, 108]\nx = ''.join([chr(c) for c in codes])"),

    # Async function (should be collected like sync)
    ("async_func",
     "async def f():\n    codes = [101, 118, 97, 108]\n    x = ''.join(chr(c) for c in codes)"),

    # Walrus / filter in comprehension: tracked var is there but comp has filter
    ("filter_in_comp",
     "codes = [101, 118, 97, 108, 0]\nx = ''.join(chr(c) for c in codes if c > 0)"),

    # Comprehension with conditional expression in element position
    ("cond_expr_elt",
     "codes = [101, 118, 97, 108]\nx = ''.join(chr(c) if c > 0 else '' for c in codes)"),

    # Large int list (should still be tracked and resolved)
    ("large_list",
     "codes = " + repr([ord(c) for c in "eval" * 25]) + "\n"
     "x = ''.join(chr(c) for c in codes)"),

    # Arithmetic inside list elements: [100+1, ...] -> AST BinOp, not Constant
    ("arithmetic_in_elts",
     "codes = [100+1, 117+1, 96+1, 107+1]\nx = ''.join(chr(c) for c in codes)"),
]


def main():
    print("=== R-EFF002 In-Scope Analysis ===\n")
    print("Testing whether _collect_int_list_assigns tracks these variables\n"
          "AND whether the comprehension resolves.\n")

    tracked_but_unresolved = []
    untracked = []
    detected = []

    for name, code in IN_SCOPE_CASES:
        tree = ast.parse(code)
        ilt = _collect_int_list_assigns(tree)
        st = build_symbol_table(tree)
        findings = detect_split_evasion(tree, _FILE, {}, st, int_list_table=ilt)
        full_findings = analyze_python(code, _FILE)

        has_exec = any(f.rule_id in ("EXEC-002", "EXEC-006") for f in findings)
        has_exec_full = any(f.rule_id in ("EXEC-002", "EXEC-006") for f in full_findings)

        # Check if 'codes' is in the int_list_table (any key containing 'codes')
        codes_tracked = any("codes" in k for k in ilt)

        status = "DETECTED" if (has_exec or has_exec_full) else "EVADED"
        track_status = "tracked" if codes_tracked else "NOT tracked"

        print(f"  [{status:8s}] [{track_status:11s}] {name}")
        if ilt:
            print(f"             int_list_table keys: {list(ilt.keys())}")

        if status == "EVADED":
            if codes_tracked:
                tracked_but_unresolved.append(name)
            else:
                untracked.append(name)
        else:
            detected.append(name)

    print(f"\n--- Summary ---")
    print(f"Total in-scope cases: {len(IN_SCOPE_CASES)}")
    print(f"Detected:             {len(detected)}")
    print(f"Evaded (untracked):   {len(untracked)} -- pre-pass gap")
    print(f"Evaded (tracked but unresolved): {len(tracked_but_unresolved)} -- resolution gap")

    if untracked:
        print(f"\nPre-pass gaps (variable NOT in int_list_table):")
        for n in untracked:
            print(f"  - {n}")
    if tracked_but_unresolved:
        print(f"\nResolution gaps (variable IN table but comprehension not resolved):")
        for n in tracked_but_unresolved:
            print(f"  - {n}")

    evasion_rate = (len(untracked) + len(tracked_but_unresolved)) / len(IN_SCOPE_CASES) * 100
    print(f"\nIn-scope evasion rate: {evasion_rate:.1f}%")


if __name__ == "__main__":
    main()
