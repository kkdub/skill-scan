"""Adversarial corpus for R-EFF002: tracked int-list chr comprehension resolution.

Each test case is a Python snippet that constructs a dangerous name ('eval', 'exec',
'system', 'popen', '__import__', 'getattr') via chr() comprehension with int lists,
using evasion techniques to bypass detection.

Categories:
  1. Variable reassignment (last-write wins)
  2. Scope confusion (cross-scope leaks, nested functions)
  3. Conditional assignment (if/for/while guards)
  4. Augmented assignment (+=, extend, append)
  5. Nested/transformed comprehension (nested listcomp, filter, etc.)
  6. Generator indirection (assigned generator, chained calls)
  7. Variable aliasing (copy, rename, tuple unpack)
  8. Type confusion (mixed types that still work at runtime)
  9. Large / boundary int lists
 10. Function aliasing (chr renamed, builtins.chr, etc.)
 11. Deeply nested scope (class in function, function in class, etc.)
 12. List construction indirection (list(), range, etc.)
 13. Arithmetic in int values (1+100, etc.)
 14. Multi-generator comprehension
 15. Walrus operator in comprehension
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_split_join_helpers import _collect_int_list_assigns
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_FILE = "adversarial.py"

# Target dangerous names and their ord values
_EVAL_ORDS = [101, 118, 97, 108]  # eval
_EXEC_ORDS = [101, 120, 101, 99]  # exec
_SYSTEM_ORDS = [115, 121, 115, 116, 101, 109]  # system
_IMPORT_ORDS = [ord(c) for c in "__import__"]  # __import__


def _detect(code: str) -> list[Finding]:
    """Run full detection pipeline."""
    tree = ast.parse(code)
    st = build_symbol_table(tree)
    ilt = _collect_int_list_assigns(tree)
    return detect_split_evasion(tree, _FILE, {}, st, int_list_table=ilt)


def _detect_full(code: str) -> list[Finding]:
    """Run full analyze_python pipeline (includes all detectors)."""
    return analyze_python(code, _FILE)


def _has_dangerous_finding(findings: list[Finding]) -> bool:
    """Check if any EXEC-002 or EXEC-006 finding was produced."""
    return any(f.rule_id in ("EXEC-002", "EXEC-006") for f in findings)


# =============================================================================
# ADVERSARIAL CORPUS
# =============================================================================

CORPUS: list[dict] = []


def case(category: str, name: str, code: str, *, should_detect: bool = True):
    """Register an adversarial test case."""
    CORPUS.append({
        "category": category,
        "name": name,
        "code": code,
        "should_detect": should_detect,
    })


# --- Category 1: Variable Reassignment ---
case("reassignment", "overwrite_safe_then_evil",
     "codes = [104, 101, 108, 108, 111]\n"  # hello
     "codes = [101, 118, 97, 108]\n"  # eval (overwrites)
     "x = ''.join(chr(c) for c in codes)")

case("reassignment", "overwrite_evil_then_safe",
     "codes = [101, 118, 97, 108]\n"  # eval
     "codes = [104, 101, 108, 108, 111]\n"  # hello (overwrites)
     "x = ''.join(chr(c) for c in codes)",
     should_detect=False)  # should NOT detect -- final value is safe

case("reassignment", "overwrite_in_function",
     "def f():\n"
     "    codes = [104, 101, 108, 108, 111]\n"  # hello
     "    codes = [101, 118, 97, 108]\n"  # eval
     "    x = ''.join(chr(c) for c in codes)")

# --- Category 2: Scope Confusion ---
case("scope_confusion", "module_var_used_in_function",
     "codes = [101, 118, 97, 108]\n"
     "def f():\n"
     "    x = ''.join(chr(c) for c in codes)")

case("scope_confusion", "function_var_shadows_module",
     "codes = [104, 101, 108, 108, 111]\n"  # hello at module
     "def f():\n"
     "    codes = [101, 118, 97, 108]\n"  # eval in function
     "    x = ''.join(chr(c) for c in codes)")

case("scope_confusion", "different_functions_same_varname",
     "def safe():\n"
     "    codes = [104, 101, 108, 108, 111]\n"
     "    x = ''.join(chr(c) for c in codes)\n"
     "def evil():\n"
     "    codes = [101, 118, 97, 108]\n"
     "    x = ''.join(chr(c) for c in codes)")

case("scope_confusion", "nested_function_uses_outer_var",
     "def outer():\n"
     "    codes = [101, 118, 97, 108]\n"
     "    def inner():\n"
     "        x = ''.join(chr(c) for c in codes)\n"
     "    inner()")

case("scope_confusion", "class_method_var",
     "class C:\n"
     "    def method(self):\n"
     "        codes = [101, 118, 97, 108]\n"
     "        x = ''.join(chr(c) for c in codes)")

# --- Category 3: Conditional Assignment ---
case("conditional", "if_branch_assignment",
     "if True:\n"
     "    codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in codes)")

case("conditional", "else_branch_assignment",
     "if False:\n"
     "    codes = [104, 101, 108, 108, 111]\n"
     "else:\n"
     "    codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in codes)")

case("conditional", "for_loop_assignment",
     "for _ in range(1):\n"
     "    codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in codes)")

case("conditional", "try_except_assignment",
     "try:\n"
     "    codes = [101, 118, 97, 108]\n"
     "except Exception:\n"
     "    pass\n"
     "x = ''.join(chr(c) for c in codes)")

case("conditional", "while_assignment",
     "while True:\n"
     "    codes = [101, 118, 97, 108]\n"
     "    break\n"
     "x = ''.join(chr(c) for c in codes)")

case("conditional", "with_block_assignment",
     "import contextlib\n"
     "with contextlib.nullcontext():\n"
     "    codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in codes)")

case("conditional", "if_in_function",
     "def f():\n"
     "    if True:\n"
     "        codes = [101, 118, 97, 108]\n"
     "    x = ''.join(chr(c) for c in codes)")

# --- Category 4: Augmented / Incremental Assignment ---
case("augmented", "plus_equals_list",
     "codes = [101, 118]\n"
     "codes += [97, 108]\n"
     "x = ''.join(chr(c) for c in codes)")

case("augmented", "extend_method",
     "codes = [101, 118]\n"
     "codes.extend([97, 108])\n"
     "x = ''.join(chr(c) for c in codes)")

case("augmented", "append_one_by_one",
     "codes = []\n"
     "codes.append(101)\n"
     "codes.append(118)\n"
     "codes.append(97)\n"
     "codes.append(108)\n"
     "x = ''.join(chr(c) for c in codes)")

case("augmented", "insert_method",
     "codes = [101, 97, 108]\n"
     "codes.insert(1, 118)\n"
     "x = ''.join(chr(c) for c in codes)")

case("augmented", "list_concat",
     "a = [101, 118]\n"
     "b = [97, 108]\n"
     "codes = a + b\n"
     "x = ''.join(chr(c) for c in codes)")

case("augmented", "list_multiply",
     "# codes constructed via multiply doesn't directly help but tests boundary\n"
     "codes = [101] * 1 + [118] * 1 + [97] * 1 + [108] * 1\n"
     "x = ''.join(chr(c) for c in codes)")

# --- Category 5: Nested / Transformed Comprehension ---
case("nested_comp", "nested_listcomp_iter",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in [x for x in codes])")

case("nested_comp", "filter_in_comprehension",
     "codes = [101, 118, 97, 108, 0]\n"
     "x = ''.join(chr(c) for c in codes if c > 0)")

case("nested_comp", "double_generator",
     "rows = [[101, 118], [97, 108]]\n"
     "x = ''.join(chr(c) for row in rows for c in row)")

case("nested_comp", "list_comp_instead_of_generator",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join([chr(c) for c in codes])")

case("nested_comp", "set_comp_evasion",
     "# set comprehension (order not guaranteed, but tests parser)\n"
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in sorted(codes))")

case("nested_comp", "dict_comp_values",
     "codes = {0: 101, 1: 118, 2: 97, 3: 108}\n"
     "x = ''.join(chr(codes[i]) for i in sorted(codes))")

case("nested_comp", "star_unpack_in_list",
     "a = [101, 118]\n"
     "b = [97, 108]\n"
     "x = ''.join(chr(c) for c in [*a, *b])")

# --- Category 6: Generator / Iterator Indirection ---
case("indirection", "assigned_generator",
     "codes = [101, 118, 97, 108]\n"
     "gen = (chr(c) for c in codes)\n"
     "x = ''.join(gen)")

case("indirection", "map_with_tracked_var",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(map(chr, codes))")

case("indirection", "list_call_wrapping",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in list(codes))")

case("indirection", "iter_call_wrapping",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in iter(codes))")

case("indirection", "reversed_tracked_var",
     "codes = [108, 97, 118, 101]\n"  # 'lave' reversed = 'eval'
     "x = ''.join(chr(c) for c in reversed(codes))")

case("indirection", "tuple_conversion",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in tuple(codes))")

# --- Category 7: Variable Aliasing ---
case("aliasing", "simple_alias",
     "original = [101, 118, 97, 108]\n"
     "codes = original\n"
     "x = ''.join(chr(c) for c in codes)")

case("aliasing", "chained_alias",
     "a = [101, 118, 97, 108]\n"
     "b = a\n"
     "c = b\n"
     "x = ''.join(chr(c) for c in c)")

case("aliasing", "tuple_unpack_alias",
     "data = ([101, 118, 97, 108], 'other')\n"
     "codes, _ = data\n"
     "x = ''.join(chr(c) for c in codes)")

case("aliasing", "dict_value_alias",
     "data = {'payload': [101, 118, 97, 108]}\n"
     "codes = data['payload']\n"
     "x = ''.join(chr(c) for c in codes)")

case("aliasing", "function_return_alias",
     "def get_codes():\n"
     "    return [101, 118, 97, 108]\n"
     "codes = get_codes()\n"
     "x = ''.join(chr(c) for c in codes)")

case("aliasing", "list_copy_alias",
     "original = [101, 118, 97, 108]\n"
     "codes = original.copy()\n"
     "x = ''.join(chr(c) for c in codes)")

case("aliasing", "slice_copy_alias",
     "original = [101, 118, 97, 108]\n"
     "codes = original[:]\n"
     "x = ''.join(chr(c) for c in codes)")

# --- Category 8: Type Confusion ---
case("type_confusion", "mixed_int_and_float",
     "codes = [101, 118.0, 97, 108]\n"  # float 118.0 not isinstance int
     "x = ''.join(chr(int(c)) for c in codes)")

case("type_confusion", "hex_int_literals",
     "codes = [0x65, 0x76, 0x61, 0x6c]\n"  # hex literals for eval
     "x = ''.join(chr(c) for c in codes)")

case("type_confusion", "octal_int_literals",
     "codes = [0o145, 0o166, 0o141, 0o154]\n"  # octal for eval
     "x = ''.join(chr(c) for c in codes)")

case("type_confusion", "binary_int_literals",
     "codes = [0b1100101, 0b1110110, 0b1100001, 0b1101100]\n"  # binary for eval
     "x = ''.join(chr(c) for c in codes)")

case("type_confusion", "negative_then_abs",
     "codes = [-101, -118, -97, -108]\n"
     "x = ''.join(chr(abs(c)) for c in codes)")

case("type_confusion", "bool_true_as_int",
     "codes = [True, 118, 97, 108]\n"  # True is int subclass, value 1
     "x = ''.join(chr(c) for c in codes)")

# --- Category 9: Large / Boundary ---
case("boundary", "large_int_list_100_elements",
     "codes = " + repr([ord(c) for c in "eval" * 25]) + "\n"
     "x = ''.join(chr(c) for c in codes)")

case("boundary", "single_char_eval_trick",
     "# Single element lists joined\n"
     "e = [101]; v = [118]; a = [97]; l = [108]\n"
     "x = ''.join(chr(c) for c in e) + ''.join(chr(c) for c in v) + "
     "''.join(chr(c) for c in a) + ''.join(chr(c) for c in l)")

case("boundary", "empty_list",
     "codes = []\n"
     "x = ''.join(chr(c) for c in codes)",
     should_detect=False)

case("boundary", "unicode_codepoints",
     "codes = [101, 118, 97, 108]\n"  # same as ASCII but explicit unicode
     "x = ''.join(chr(c) for c in codes)")

# --- Category 10: Function / chr Aliasing ---
case("chr_aliasing", "chr_assigned_to_variable",
     "codes = [101, 118, 97, 108]\n"
     "f = chr\n"
     "x = ''.join(f(c) for c in codes)")

case("chr_aliasing", "builtins_chr",
     "import builtins\n"
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(builtins.chr(c) for c in codes)")

case("chr_aliasing", "chr_via_getattr",
     "import builtins\n"
     "codes = [101, 118, 97, 108]\n"
     "my_chr = getattr(builtins, 'chr')\n"
     "x = ''.join(my_chr(c) for c in codes)")

case("chr_aliasing", "lambda_wrapper",
     "codes = [101, 118, 97, 108]\n"
     "to_char = lambda x: chr(x)\n"
     "x = ''.join(to_char(c) for c in codes)")

case("chr_aliasing", "from_builtins_import_chr",
     "from builtins import chr as my_chr\n"
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(my_chr(c) for c in codes)")

# --- Category 11: Deep Nesting ---
case("deep_nesting", "class_in_function",
     "def f():\n"
     "    class C:\n"
     "        codes = [101, 118, 97, 108]\n"
     "        x = ''.join(chr(c) for c in codes)")

case("deep_nesting", "function_in_function",
     "def outer():\n"
     "    def inner():\n"
     "        codes = [101, 118, 97, 108]\n"
     "        x = ''.join(chr(c) for c in codes)")

case("deep_nesting", "triple_nested_function",
     "def a():\n"
     "    def b():\n"
     "        def c():\n"
     "            codes = [101, 118, 97, 108]\n"
     "            x = ''.join(chr(c) for c in codes)")

case("deep_nesting", "async_function",
     "async def f():\n"
     "    codes = [101, 118, 97, 108]\n"
     "    x = ''.join(chr(c) for c in codes)")

# --- Category 12: List Construction Indirection ---
case("list_construction", "list_constructor",
     "codes = list((101, 118, 97, 108))\n"
     "x = ''.join(chr(c) for c in codes)")

case("list_construction", "list_from_range",
     "# range doesn't produce eval but tests handling\n"
     "codes = list(range(101, 105))\n"
     "x = ''.join(chr(c) for c in codes)",
     should_detect=False)

case("list_construction", "list_from_map",
     "codes = list(map(int, ['101', '118', '97', '108']))\n"
     "x = ''.join(chr(c) for c in codes)")

case("list_construction", "bytearray_to_list",
     "codes = list(bytearray(b'eval'))\n"
     "x = ''.join(chr(c) for c in codes)")

case("list_construction", "struct_unpack",
     "import struct\n"
     "codes = list(struct.unpack('4B', b'eval'))\n"
     "x = ''.join(chr(c) for c in codes)")

# --- Category 13: Arithmetic in Int Values ---
case("arithmetic_ints", "addition_in_list",
     "codes = [100+1, 117+1, 96+1, 107+1]\n"
     "x = ''.join(chr(c) for c in codes)")

case("arithmetic_ints", "xor_in_list",
     "key = 0xFF\n"
     "codes = [101 ^ key, 118 ^ key, 97 ^ key, 108 ^ key]\n"
     "# runtime: [c ^ key for c in codes] = eval\n"
     "x = ''.join(chr(c ^ 0xFF) for c in codes)")

case("arithmetic_ints", "subtraction_encoding",
     "codes = [201, 218, 197, 208]\n"  # each + 100
     "x = ''.join(chr(c - 100) for c in codes)")

# --- Category 14: Multi-generator / Complex Comprehension ---
case("complex_comp", "walrus_in_comp",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) for c in codes if (y := c) > 0)")

case("complex_comp", "conditional_expr_in_elt",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(chr(c) if c > 0 else '' for c in codes)")

case("complex_comp", "str_format_chr",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join('{}'.format(chr(c)) for c in codes)")

case("complex_comp", "f_string_chr",
     "codes = [101, 118, 97, 108]\n"
     "x = ''.join(f'{chr(c)}' for c in codes)")

# --- Category 15: Semantic Equivalents (no chr) ---
case("semantic_equiv", "bytes_decode",
     "codes = [101, 118, 97, 108]\n"
     "x = bytes(codes).decode()")

case("semantic_equiv", "bytearray_decode",
     "codes = [101, 118, 97, 108]\n"
     "x = bytearray(codes).decode()")

case("semantic_equiv", "struct_pack_unpack",
     "import struct\n"
     "codes = [101, 118, 97, 108]\n"
     "x = struct.pack('4B', *codes).decode()")

case("semantic_equiv", "array_module",
     "import array\n"
     "codes = [101, 118, 97, 108]\n"
     "a = array.array('B', codes)\n"
     "x = a.tobytes().decode()")


def run_corpus():
    """Run all adversarial inputs and measure evasion rates."""
    results = {
        "total": 0,
        "evaded": 0,
        "detected": 0,
        "false_positives": 0,
        "errors": 0,
        "by_category": {},
        "evasions": [],
        "false_pos_list": [],
    }

    for case_data in CORPUS:
        cat = case_data["category"]
        name = case_data["name"]
        code = case_data["code"]
        should_detect = case_data["should_detect"]

        if cat not in results["by_category"]:
            results["by_category"][cat] = {"total": 0, "evaded": 0, "detected": 0, "false_pos": 0, "errors": 0}

        results["total"] += 1
        results["by_category"][cat]["total"] += 1

        try:
            findings = _detect_full(code)
            detected = _has_dangerous_finding(findings)

            if should_detect and detected:
                results["detected"] += 1
                results["by_category"][cat]["detected"] += 1
            elif should_detect and not detected:
                results["evaded"] += 1
                results["by_category"][cat]["evaded"] += 1
                results["evasions"].append({
                    "category": cat,
                    "name": name,
                    "code": code,
                    "findings": [f.rule_id for f in findings],
                })
            elif not should_detect and detected:
                results["false_positives"] += 1
                results["by_category"][cat]["false_pos"] += 1
                results["false_pos_list"].append({
                    "category": cat,
                    "name": name,
                    "code": code,
                    "findings": [f.rule_id for f in findings],
                })
            else:
                # Correctly not detected
                results["detected"] += 1
                results["by_category"][cat]["detected"] += 1
        except Exception as e:
            results["errors"] += 1
            results["by_category"][cat]["errors"] += 1
            results["evasions"].append({
                "category": cat,
                "name": name,
                "code": code,
                "error": str(e),
            })

    return results


def print_report(results: dict) -> None:
    """Print formatted evasion report."""
    total = results["total"]
    evaded = results["evaded"]
    detected = results["detected"]
    fp = results["false_positives"]
    errors = results["errors"]

    rate = (evaded / total * 100) if total > 0 else 0

    print(f"Status: {'FAIL' if evaded > 0 else 'PASS'}")
    print(f"Overall evasion rate: {rate:.1f}%")
    print(f"Regression candidates: {evaded} inputs")
    print()
    print("## Red-Team Report")
    print()
    print("**Target:** _ast_split_join_helpers._resolve_comprehension_join + _collect_int_list_assigns")
    print("**Domain:** security scanner (obfuscated string construction via chr comprehension)")
    print("**Logic reviewed:** _ast_split_join_helpers.py, _ast_split_detector.py, ast_analyzer.py, _ast_symbol_table.py")
    print()
    print("### Evasion Results")
    print(f"| Category | Inputs | Evaded | Rate |")
    print(f"|----------|--------|--------|------|")
    for cat, data in sorted(results["by_category"].items()):
        cat_rate = (data["evaded"] / data["total"] * 100) if data["total"] > 0 else 0
        print(f"| {cat} | {data['total']} | {data['evaded']} | {cat_rate:.0f}% |")
    print(f"| **Total** | {total} | {evaded} | {rate:.0f}% |")
    print()

    if results["evasions"]:
        print("### Evasion Details")
        for ev in results["evasions"]:
            print(f"\n**[{ev['category']}] {ev['name']}**")
            if "error" in ev:
                print(f"  ERROR: {ev['error']}")
            else:
                print(f"  Findings produced: {ev.get('findings', [])}")
            print(f"  Code:")
            for line in ev["code"].split("\n"):
                print(f"    {line}")
    print()

    if results["false_pos_list"]:
        print("### False Positives")
        for fp_item in results["false_pos_list"]:
            print(f"\n**[{fp_item['category']}] {fp_item['name']}**")
            print(f"  Findings: {fp_item['findings']}")
            print(f"  Code:")
            for line in fp_item["code"].split("\n"):
                print(f"    {line}")


if __name__ == "__main__":
    results = run_corpus()
    print_report(results)

    # Save structured results
    out_dir = Path(__file__).parent
    results_file = out_dir / "results.json"
    # Strip non-serializable data
    save_data = {k: v for k, v in results.items()}
    with open(results_file, "w") as f:
        json.dump(save_data, f, indent=2)
    print(f"\nResults saved to: {results_file}")
