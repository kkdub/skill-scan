#!/usr/bin/env python3
"""Check Python files for antipatterns that require AST analysis.

This script detects patterns that cannot be caught by regex alone and are not
covered by ruff or mypy. Each check analyzes the AST structure of Python files.

Implemented patterns:
- DATA-001: @dataclass without slots=True
- CONTROL-001: 3+ elif branches (suggest match statement)
- TYPE-003: Use Self instead of string class name for return type
- INHERIT-001: Override methods should use @override decorator
- INHERIT-002: Deep inheritance hierarchy (3+ levels)
- SIZE-002: Function exceeds line limit

Exit codes:
- 0: No violations at or above fail-on severity
- 1: Violations found at or above fail-on severity
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import TYPE_CHECKING

# Add repo root to sys.path for imports when running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.ast_checks.models import (
    EXCLUDE_DIRS,
    SEVERITY_LEVELS,
    SEVERITY_SYMBOLS,
    Stats,
    Violation,
)
from scripts.ast_checks.visitor import AntipatternVisitor

if TYPE_CHECKING:
    from collections.abc import Iterator


def walk_python_files(root: Path) -> Iterator[Path]:
    """Yield Python files, skipping excluded directories."""
    for path in root.rglob("*.py"):
        if not any(excl in path.parts for excl in EXCLUDE_DIRS):
            yield path


def check_file(file_path: Path) -> list[Violation]:
    """Check a single file for AST antipattern violations."""
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
    except (OSError, UnicodeDecodeError, SyntaxError) as e:
        print(f"Warning: Could not process {file_path}: {e}", file=sys.stderr)
        return []

    visitor = AntipatternVisitor(file_path)
    visitor.visit(tree)
    return visitor.violations


def format_violation(v: Violation, verbose: bool = False) -> str:
    """Format a violation for display."""
    symbol = SEVERITY_SYMBOLS.get(v.severity, "[?]")
    header = f"{symbol} {v.file}:{v.line}: {v.name}"
    if not verbose:
        return f"{header} - {v.message}"
    return (
        f"\n{'=' * 70}\n  {header}\n{'=' * 70}\n"
        f"  Rule: {v.rule_id}\n  Severity: {v.severity.upper()}\n  {v.message}\n"
    )


def _create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(description="Check Python files for AST-based antipatterns.")
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Python files or directories to check (reads from stdin if none)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--min-severity", choices=["info", "warning", "error"], default="info")
    parser.add_argument("--fail-on", choices=["info", "warning", "error"], default="error")
    parser.add_argument("--exclude-rule", action="append", default=[], dest="exclude_rules")
    return parser


def _collect_files(paths: list[Path]) -> list[Path]:
    """Collect Python files from paths or stdin."""
    if not paths:
        paths = [Path(line.strip()) for line in sys.stdin if line.strip()]
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(walk_python_files(path))
        elif path.suffix == ".py" and path.exists():
            files.append(path)
    return files


def _filter_violations(
    violations: list[Violation], min_severity: str, exclude_rules: list[str]
) -> list[Violation]:
    """Filter violations by severity and exclusion rules."""
    min_level = SEVERITY_LEVELS[min_severity]
    exclude_set = set(exclude_rules)
    return [
        v
        for v in violations
        if SEVERITY_LEVELS.get(v.severity, 0) >= min_level and v.rule_id not in exclude_set
    ]


def _report_violations(violations: list[Violation], verbose: bool, fail_on: str) -> int:
    """Report violations and return exit code."""
    if not violations:
        return 0

    stats = Stats()
    for v in violations:
        stats.add(v.severity)

    print(f"\nFound {len(violations)} AST antipattern violation(s):\n")

    sorted_violations = sorted(
        violations, key=lambda x: (-SEVERITY_LEVELS.get(x.severity, 0), x.file, x.line)
    )
    for v in sorted_violations:
        print(format_violation(v, verbose))

    print(f"\nSummary: {stats.errors} errors, {stats.warnings} warnings, {stats.infos} info")

    fail_level = SEVERITY_LEVELS[fail_on]
    has_failures = any(SEVERITY_LEVELS.get(v.severity, 0) >= fail_level for v in violations)
    return 1 if has_failures else 0


def main() -> int:
    """Main entry point."""
    args = _create_parser().parse_args()
    files = _collect_files(args.paths)
    if not files:
        return 0

    all_violations: list[Violation] = []
    for file_path in files:
        all_violations.extend(check_file(file_path))

    filtered = _filter_violations(all_violations, args.min_severity, args.exclude_rules)
    return _report_violations(filtered, args.verbose, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
