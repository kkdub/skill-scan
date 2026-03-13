#!/usr/bin/env python3
"""Check Python files for code pattern violations.

This script reads patterns from .agent/standards/code-rules.json and scans
Python files for matches. Each pattern includes:
- pattern: identifier name
- severity: error, warning, or info
- antipattern: regex to detect the issue
- description: what the issue is
- fix: how to fix it
- explanation: why it matters
- context_check: optional, specifies context-aware validation

Exit codes:
- 0: No violations at or above minimum severity
- 1: Violations found at or above minimum severity
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Add repo root to sys.path for imports when running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts._pattern_rules import CONTEXT_CHECK_TRY_EXCEPT, Pattern, load_patterns
from scripts.antipattern_context import is_in_try_except_block

# Severity levels (higher = more severe)
SEVERITY_LEVELS = {"info": 1, "warning": 2, "error": 3}
SEVERITY_SYMBOLS = {"info": "[I]", "warning": "[W]", "error": "[E]"}


_NOQA_RE = re.compile(r"#\s*noqa(?::\s*([A-Z][\w,-]+))?")


@dataclass(slots=True, frozen=True)
class Violation:
    """A detected violation in a file."""

    file: Path
    line_num: int
    line_content: str
    pattern: Pattern


@dataclass(slots=True)
class Stats:
    """Violation statistics by severity."""

    errors: int = 0
    warnings: int = 0
    infos: int = 0

    def add(self, severity: str) -> None:
        """Increment counter for given severity."""
        if severity == "error":
            self.errors += 1
        elif severity == "warning":
            self.warnings += 1
        else:
            self.infos += 1


def find_line_number(content: str, match_start: int) -> int:
    """Find the line number for a match position."""
    return content[:match_start].count("\n") + 1


def check_file(file_path: Path, patterns: list[Pattern]) -> list[Violation]:
    """Check a single file for code pattern violations."""
    violations: list[Violation] = []

    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return violations

    lines = content.splitlines()

    for pattern in patterns:
        for match in pattern.regex.finditer(content):
            line_num = find_line_number(content, match.start())
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""

            noqa_match = _NOQA_RE.search(line_content)
            if noqa_match:
                codes = noqa_match.group(1)
                if codes is None or pattern.rule_id in codes.split(","):
                    continue

            if pattern.context_check == CONTEXT_CHECK_TRY_EXCEPT and is_in_try_except_block(
                lines,
                line_num,
                pattern.context_exception,
            ):
                continue

            violations.append(
                Violation(
                    file=file_path,
                    line_num=line_num,
                    line_content=line_content.strip(),
                    pattern=pattern,
                ),
            )

    return violations


def format_violation(v: Violation, verbose: bool = False) -> str:
    """Format a violation for display."""
    symbol = SEVERITY_SYMBOLS.get(v.pattern.severity, "•")
    location = f"{v.file}:{v.line_num}"
    header = f"{symbol} {location}: {v.pattern.name}"

    if not verbose:
        return f"{header} - {v.pattern.description}"

    lines = [
        f"\n{'=' * 70}",
        f"  {header}",
        f"{'=' * 70}",
        f"  Severity: {v.pattern.severity.upper()}",
        f"  Description: {v.pattern.description}",
        f"  Line {v.line_num}: {v.line_content}",
        f"  Fix: {v.pattern.fix}",
        f"  Why: {v.pattern.explanation}",
    ]
    return "\n".join(lines)


def _create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Check Python files for code pattern violations.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="Python files to check (reads from stdin if none provided)",
    )
    parser.add_argument(
        "--patterns",
        type=Path,
        default=Path(".agent/standards/code-rules.json"),
        help="Path to code rules JSON file (default: .agent/standards/code-rules.json)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed violation information",
    )
    parser.add_argument(
        "--min-severity",
        choices=["info", "warning", "error"],
        default="warning",
        help="Minimum severity to report (default: warning)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["info", "warning", "error"],
        default="error",
        help="Minimum severity to fail on (default: error)",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        action="append",
        default=[],
        help="Pattern names to exclude (can be repeated)",
    )
    return parser


def _find_patterns_file(patterns_arg: Path) -> Path | None:
    """Find patterns file, checking multiple locations."""
    if patterns_arg.exists():
        return patterns_arg
    script_dir = Path(__file__).parent.parent
    alt_path = script_dir / ".agent" / "standards" / "code-rules.json"
    return alt_path if alt_path.exists() else None


def _filter_patterns(
    all_patterns: list[Pattern],
    min_severity: str,
    exclude: list[str],
) -> list[Pattern]:
    """Filter patterns by severity and exclusion list."""
    min_level = SEVERITY_LEVELS[min_severity]
    patterns = [p for p in all_patterns if SEVERITY_LEVELS.get(p.severity, 0) >= min_level]
    if exclude:
        exclude_set = set(exclude)
        patterns = [p for p in patterns if p.name not in exclude_set]
    return patterns


def _get_python_files(files: list[Path]) -> list[Path]:
    """Get list of Python files to check."""
    if not files:
        files = [Path(line.strip()) for line in sys.stdin if line.strip()]
    return [f for f in files if f.suffix == ".py" and f.exists()]


def _report_violations(violations: list[Violation], verbose: bool, fail_on: str) -> int:
    """Report violations and return exit code."""
    if not violations:
        return 0

    stats = Stats()
    for v in violations:
        stats.add(v.pattern.severity)

    print(f"\nFound {len(violations)} code pattern violation(s):\n")

    def sort_key(v: Violation) -> tuple[int, Path, int]:
        return (-SEVERITY_LEVELS.get(v.pattern.severity, 0), v.file, v.line_num)

    for v in sorted(violations, key=sort_key):
        print(format_violation(v, verbose=verbose))

    print(f"\nSummary: {stats.errors} errors, {stats.warnings} warnings, {stats.infos} info")

    if not verbose:
        print("\nRun with --verbose for detailed fix suggestions.")

    fail_level = SEVERITY_LEVELS[fail_on]
    has_failures = any(SEVERITY_LEVELS.get(v.pattern.severity, 0) >= fail_level for v in violations)
    return 1 if has_failures else 0


def main() -> int:
    """Main entry point."""
    parser = _create_argument_parser()
    args = parser.parse_args()

    patterns_file = _find_patterns_file(args.patterns)
    if not patterns_file:
        print(f"Error: Patterns file not found: {args.patterns}", file=sys.stderr)
        return 1

    all_patterns = load_patterns(patterns_file)
    if not all_patterns:
        print("Error: No valid patterns loaded", file=sys.stderr)
        return 1

    patterns = _filter_patterns(all_patterns, args.min_severity, args.exclude)
    python_files = _get_python_files(args.files)

    if not python_files:
        return 0

    all_violations: list[Violation] = []
    for file_path in python_files:
        all_violations.extend(check_file(file_path, patterns))

    return _report_violations(all_violations, args.verbose, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
