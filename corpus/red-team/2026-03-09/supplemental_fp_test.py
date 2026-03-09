"""Supplemental false positive tests discovered during adversarial analysis.

Validates that the AST analyzer does NOT flag safe code patterns (plain string
literals, dict keys, comparisons, safe loaders) as dangerous -- only actual
dynamic code construction should trigger findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from skill_scan.ast_analyzer import analyze_python

_FILE = "fp_test.py"

# All of these are FALSE POSITIVES -- safe code that should NOT be flagged.
FP_CASES = [
    ("name = 'eval'\n", "Plain string literal 'eval'"),
    ("name = 'exec'\n", "Plain string literal 'exec'"),
    ("name = 'system'\n", "Plain string literal 'system'"),
    ("name = 'popen'\n", "Plain string literal 'popen'"),
    ("name = 'getattr'\n", "Plain string literal 'getattr'"),
    ("d = {'eval': True}\n", "Dict key 'eval'"),
    ("if mode == 'eval': pass\n", "Comparison with 'eval' string"),
    ("MODES = ['eval', 'exec', 'predict']\n", "List containing 'eval'/'exec'"),
    ("x = 'system' + '_config'\n", "Concat building 'system_config'"),
    ("log.info('entering eval mode')\n", "Log message containing 'eval'"),
    ("import yaml\nyaml.load(data, yaml.SafeLoader)\n",
     "yaml.load with positional SafeLoader (safe but flagged)"),
]


def run():
    total = 0
    fps = 0
    for code, desc in FP_CASES:
        findings = analyze_python(code, _FILE)
        total += 1
        if findings:
            fps += 1
            print(f"  FALSE POSITIVE: {desc}")
            for f in findings:
                print(f"    {f.rule_id}: {f.matched_text}")
        else:
            print(f"  OK: {desc}")

    print(f"\nTotal: {total}, False positives: {fps}, FP rate: {fps/total*100:.1f}%")
    return fps


if __name__ == "__main__":
    count = run()
    sys.exit(1 if count > 0 else 0)
