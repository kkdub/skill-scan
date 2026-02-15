#!/usr/bin/env python3
r"""Pre-commit hook to detect direct float equality comparisons in tests.

This catches a common issue in test suites:
    assert result == 0.5  # BAD - floating point precision issues

Should be:
    assert result == pytest.approx(0.5)  # GOOD

Usage in .pre-commit-config.yaml:
    - repo: local
      hooks:
        - id: check-float-equality
          name: "Check Float Equality in Tests"
          entry: python scripts/check_float_equality.py
          language: system
          files: ^tests/.*\.py$
          pass_filenames: true
"""

import re
import sys
from pathlib import Path

# Patterns that indicate float equality (problematic)
FLOAT_PATTERNS = [
    # assert x == 0.5 or assert 0.5 == x
    r"assert\s+\w+\s*==\s*\d+\.\d+",
    r"assert\s+\d+\.\d+\s*==\s*\w+",
    # assertEqual(x, 0.5)
    r"assertEqual\s*\(\s*\w+\s*,\s*\d+\.\d+\s*\)",
    r"assertEqual\s*\(\s*\d+\.\d+\s*,\s*\w+\s*\)",
    # x == 0.5 in conditions
    r"if\s+.*\w+\s*==\s*\d+\.\d+",
]

# Patterns that are OK (using approx)
SAFE_PATTERNS = [
    r"pytest\.approx",
    r"approx\(",
    r"math\.isclose",
    r"numpy\.isclose",
    r"np\.isclose",
    r"assertAlmostEqual",
    r"# noqa",
    r"# type:",
]


def check_file(filepath: str) -> list[tuple[int, str]]:
    """Check a file for float equality issues."""
    issues: list[tuple[int, str]] = []

    try:
        content = Path(filepath).read_text(encoding="utf-8")
        lines = content.split("\n")
    except Exception as e:
        return [(0, f"Could not read file: {e}")]

    for line_num, line in enumerate(lines, 1):
        # Skip if line has safe pattern
        if any(re.search(pat, line) for pat in SAFE_PATTERNS):
            continue

        # Check for problematic patterns
        for pattern in FLOAT_PATTERNS:
            if re.search(pattern, line):
                issues.append((line_num, line.strip()))
                break

    return issues


def main() -> int:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: check_float_equality.py <file1> [file2] ...")
        return 0

    files = sys.argv[1:]
    total_issues = 0

    for filepath in files:
        issues = check_file(filepath)
        if issues:
            print(f"\n{filepath}:")
            for line_num, line in issues:
                print(f"  Line {line_num}: {line[:70]}...")
                print("  -> Use pytest.approx() for float comparisons")
            total_issues += len(issues)

    if total_issues > 0:
        print(f"\nFound {total_issues} float equality issue(s)")
        print("Fix: assert x == pytest.approx(expected)")
        print("Or:  assert math.isclose(x, expected)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
