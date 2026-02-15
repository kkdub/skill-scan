#!/usr/bin/env python3
"""Detect mixed decision/infrastructure code at function level using AST.

This script identifies functions where business logic (decision signals) is
mixed with infrastructure concerns (I/O operations). Such mixing makes code
harder to test and violates separation of concerns.

Usage:
    python -m scripts.arch_smell.audit              # Scan entire repo
    python -m scripts.arch_smell.audit --diff       # Only changed files
    python -m scripts.arch_smell.audit --limit 30   # Top 30 results
    python -m scripts.arch_smell.audit --verbose    # Show matched nodes
    python -m scripts.arch_smell.audit --severity critical  # Only critical
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from .analysis import FunctionResult, scan_file
from .constants import EXCLUDED_DIRS, Severity
from .git import GitError, git_diff_files, git_tracked_files


def is_excluded(path: Path) -> bool:
    """Check if path should be excluded."""
    parts = set(path.parts)
    return bool(parts & EXCLUDED_DIRS)


def scan_repo(
    repo_root: Path,
    *,
    diff_only: bool = False,
    min_severity: Severity | None = None,
) -> list[FunctionResult]:
    """Scan repository for mixed functions.

    Args:
        repo_root: Repository root path.
        diff_only: Only scan files changed in git diff.
        min_severity: Minimum severity to include. None includes all.
            CRITICAL = only critical, WARNING = warning+critical, INFO = all.

    Returns:
        List of FunctionResult sorted by effective_score (highest first).
    """
    files = git_diff_files(repo_root) if diff_only else git_tracked_files(repo_root)

    results: list[FunctionResult] = []
    for path in files:
        if is_excluded(path):
            continue
        if not path.exists():
            continue
        results.extend(scan_file(path))

    # Filter by severity if specified
    if min_severity is not None:
        severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        min_order = severity_order[min_severity]
        results = [r for r in results if severity_order[r.severity] <= min_order]

    # Sort by effective_score (highest first)
    results.sort(key=lambda r: r.effective_score, reverse=True)
    return results


def format_summary(results: list[FunctionResult]) -> str:
    """Generate category and severity summary."""
    if not results:
        return "No mixed functions found."

    # Infra category breakdown
    category_counts: Counter[str] = Counter()
    for result in results:
        for signal in result.infra_signals:
            category_counts[signal.category] += 1

    infra_parts = [f"{cat}: {count}" for cat, count in category_counts.most_common()]

    # Severity breakdown
    severity_counts: Counter[str] = Counter()
    for result in results:
        severity_counts[result.severity.value] += 1

    severity_parts = []
    for sev in [Severity.CRITICAL, Severity.WARNING, Severity.INFO]:
        if severity_counts[sev.value]:
            severity_parts.append(f"{sev.value}: {severity_counts[sev.value]}")

    lines = [
        f"Infra breakdown: {', '.join(infra_parts)}",
        f"Severity breakdown: {', '.join(severity_parts)}",
    ]
    return "\n".join(lines)


def severity_symbol(severity: Severity) -> str:
    """Return a symbol for the severity level."""
    return {
        Severity.CRITICAL: "!!!",
        Severity.WARNING: "!",
        Severity.INFO: "~",
    }[severity]


def print_results(
    results: list[FunctionResult],
    repo_root: Path,
    *,
    limit: int,
    verbose: bool,
) -> None:
    """Print results to stdout."""
    if not results:
        print("No mixed decision/infrastructure functions found.")
        return

    shown = results[:limit]
    print(f"Found {len(results)} mixed functions (showing top {len(shown)}):\n")

    for rank, result in enumerate(shown, 1):
        location = result.format_location(repo_root)
        decision_kinds = sorted({s.kind for s in result.decision_signals})
        infra_cats = sorted({s.category for s in result.infra_signals})
        sev_sym = severity_symbol(result.severity)

        print(f"{rank:3}. [{sev_sym}] {location}")
        decision_count = len(result.decision_signals)
        print(f"     Decision: {', '.join(decision_kinds)} ({decision_count} signals)")
        print(f"     Infra: {', '.join(infra_cats)} ({len(result.infra_signals)} calls)")
        print(
            f"     Score: {result.score} | Density: {result.density:.1f} | "
            f"Lines: {result.line_count} | Severity: {result.severity.value}"
        )

        if verbose:
            print("     Details:")
            for sig in result.infra_signals[:5]:
                print(f"       L{sig.line}: {sig.call}")
            if len(result.infra_signals) > 5:
                print(f"       ... and {len(result.infra_signals) - 5} more")
        print()

    print(f"\n{format_summary(results)}")
    print("\nLegend: [!!!] = critical, [!] = warning, [~] = info (glue layer)")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Find functions with mixed decision logic and infrastructure I/O.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Scan entire repo (all severities)
  %(prog)s --severity critical    Only critical-severity smells
  %(prog)s --severity warning     Warning and critical smells
  %(prog)s --diff                 Only scan changed files
  %(prog)s --verbose              Show matched I/O calls

Severity levels:
  critical (!!!): Core domain code - mixing here is a serious problem
  warning (!):    Service/data layer - mixing should be reviewed
  info (~):       Infrastructure/glue - mixing is often acceptable
        """,
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum functions to report (default: 20)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Only scan files changed in git diff",
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "warning", "info"],
        default=None,
        help="Minimum severity to include (default: all). "
        "'critical' = only critical, 'warning' = warning+critical, 'info' = all",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed signal information",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any mixed functions found (for CI/pre-commit)",
    )
    parser.add_argument(
        "--strict-critical",
        action="store_true",
        help="Exit with code 1 only if critical-severity functions found",
    )
    # Legacy flag for backward compatibility
    parser.add_argument(
        "--include-glue",
        action="store_true",
        help="(Legacy) Include all severity levels (same as --severity info)",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]

    # Determine severity filter
    min_severity: Severity | None = None
    if args.severity:
        min_severity = Severity(args.severity)
    elif args.include_glue:
        min_severity = Severity.INFO  # Include all
    else:
        # Default: show all severities
        min_severity = None

    try:
        results = scan_repo(
            repo_root,
            diff_only=args.diff,
            min_severity=min_severity,
        )
    except GitError as e:
        print(f"Git error: {e.message}", file=sys.stderr)
        return 1

    print_results(results, repo_root, limit=args.limit, verbose=args.verbose)

    # Check for failures
    if args.strict_critical:
        critical_count = sum(1 for r in results if r.severity == Severity.CRITICAL)
        if critical_count:
            print(
                f"\n❌ Found {critical_count} CRITICAL mixed functions. These must be refactored.",
                file=sys.stderr,
            )
            return 1
    elif args.strict and results:
        msg = f"\n❌ Found {len(results)} mixed functions."
        msg += " Refactor to separate decision logic from I/O."
        print(msg, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
