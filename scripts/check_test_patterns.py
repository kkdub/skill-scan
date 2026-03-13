#!/usr/bin/env python3
r"""Pre-commit hook to enforce test writing standards from test-rules.json.

Catches common test antipatterns that slip through when the test-writer
subagent is not invoked. Per-line rules use regex; TEST-010 uses ast.parse().

Rules enforced:
    TEST-001: No magic HTTP status codes (200, 404, etc.)
    TEST-002: No @pytest.mark.asyncio (redundant with asyncio_mode="auto")
    TEST-003: No time.sleep() — use time_machine
    TEST-004: No @patch on httpx internals — use respx
    TEST-006: No broad pytest.raises(Exception)
    TEST-007: Behavior-driven test names (not just test_<word>)
    TEST-008: No patching the module under test
    TEST-010: Every test function must have assertions

Skips TEST-005 (float equality) — already covered by check_float_equality.py.

Usage in .pre-commit-config.yaml:
    - repo: local
      hooks:
        - id: check-test-patterns
          name: Check Test Patterns
          entry: uv run python scripts/check_test_patterns.py
          language: system
          files: ^tests/.*\.py$
          pass_filenames: true
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add repo root to sys.path for imports when running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts._test_pattern_rules import (
    RULES,
    FileContext,
    Violation,
    check_missing_assertions,
)

# --- Main logic ---

SEVERITY_ORDER = {"error": 2, "warning": 1}


def check_file(filepath: Path) -> list[Violation]:
    """Check a single test file for violations."""
    violations: list[Violation] = []

    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(f"Warning: Could not read {filepath}: {e}", file=sys.stderr)
        return violations

    lines = content.splitlines()

    for line_idx, line in enumerate(lines):
        for rule in RULES:
            if rule.pattern.search(line):
                if rule.skip_if and rule.skip_if(line, lines, line_idx):
                    continue
                violations.append(
                    Violation(
                        file=filepath,
                        line_num=line_idx + 1,
                        line_content=line.strip(),
                        rule=rule,
                    ),
                )

    ctx = FileContext(path=filepath, lines=lines)
    violations.extend(check_missing_assertions(ctx))

    return violations


def _print_report(violations: list[Violation]) -> int:
    """Print violation report and return exit code."""
    violations.sort(
        key=lambda v: (-SEVERITY_ORDER.get(v.rule.severity, 0), v.file, v.line_num),
    )

    errors = sum(1 for v in violations if v.rule.severity == "error")
    warnings = sum(1 for v in violations if v.rule.severity == "warning")

    print(f"\nFound {len(violations)} test pattern violation(s):\n")

    for v in violations:
        severity_tag = "[E]" if v.rule.severity == "error" else "[W]"
        print(f"{severity_tag} {v.file}:{v.line_num}: {v.rule.rule_id} {v.rule.name}")
        print(f"    {v.line_content[:80]}")
        print(f"    -> {v.rule.message}")
        print(f"    Fix: {v.rule.fix}")
        print()

    print(f"Summary: {errors} errors, {warnings} warnings")
    if errors:
        print("\nErrors must be fixed before committing.")

    return 1 if errors > 0 else 0


def main() -> int:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: check_test_patterns.py <file1> [file2] ...")
        return 0

    files = [Path(f) for f in sys.argv[1:] if Path(f).suffix == ".py" and Path(f).exists()]
    if not files:
        return 0

    all_violations: list[Violation] = []
    for filepath in files:
        all_violations.extend(check_file(filepath))

    if not all_violations:
        return 0

    return _print_report(all_violations)


if __name__ == "__main__":
    sys.exit(main())
