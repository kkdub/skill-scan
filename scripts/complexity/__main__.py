"""Unified CLI entry point for complexity analysis.

Used by both pre-commit hooks and CI. Checks:
- File length > 500 lines (HIGH severity)
- Function length > 100 lines (MEDIUM severity)
- Cyclomatic complexity > 10 (MEDIUM), > 15 (HIGH), > 20 (CRITICAL)
- Maintainability Index < 40 (MEDIUM), < 35 (HIGH), < 25 (CRITICAL)

Usage:
    python -m scripts.complexity                              # Check all
    python -m scripts.complexity file1.py file2.py            # Check specific
    python -m scripts.complexity --json                       # JSON output
    python -m scripts.complexity --min-severity medium        # Filter

Based on CLAUDE.md: Files <500 lines, functions <50 lines (max 100)
See also: .agent/standards/CODE-PATTERNS.md SIZE-001, SIZE-002
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from scripts.complexity.analyzer import CodeAnalyzer, Thresholds
from scripts.complexity.models import AnalysisResult, Severity, Violation

# Files permanently exempt (documented in .agent/standards/CODE-PATTERNS.md SIZE-001)
# mcp_tools.py is the designated consolidation file for all MCP tool definitions
# It intentionally exceeds 500 lines to keep all tools discoverable in one place
EXEMPT_FILES: list[str] = ["src/server/mcp_tools.py"]

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def format_violation(violation: Violation) -> str:
    """Format a single violation for display."""
    severity_prefix = f"[{violation.severity.name}]"
    location = f"{violation.line}: " if violation.line is not None else ""
    return f"  {severity_prefix:10} {location}{violation.message}"


def _print_pass_message(result: AnalysisResult, min_severity: Severity) -> None:
    """Print pass message when no violations at min_severity level."""
    summary = result.summary()
    total = sum(summary.values())
    if total > 0:
        print(
            f"Code quality check passed ({total} violations below {min_severity.name} threshold)",
            file=sys.stderr,
        )
    else:
        print("Code quality check passed", file=sys.stderr)


def _print_summary_header(
    violations: list[Violation], summary: dict[str, int], min_severity: Severity
) -> None:
    """Print summary header with violation counts by severity."""
    summary_parts = []
    for sev in Severity:
        count = summary[sev.name.lower()]
        if count > 0 and sev <= min_severity:
            summary_parts.append(f"{count} {sev.name.lower()}")

    print("Code Quality Check Failed", file=sys.stderr)
    print(
        f"\nFound {len(violations)} violations: {', '.join(summary_parts)}",
        file=sys.stderr,
    )
    print("(See CLAUDE.md for standards)\n", file=sys.stderr)


def _print_violations_by_file(result: AnalysisResult, min_severity: Severity) -> None:
    """Print violations grouped by file, filtered by min_severity."""
    by_file = result.get_violations_by_file()
    for file_path, file_violations in by_file.items():
        filtered = [v for v in file_violations if v.severity <= min_severity]
        if not filtered:
            continue

        print(f"{file_path}:", file=sys.stderr)
        for violation in filtered:
            print(format_violation(violation), file=sys.stderr)
        print(file=sys.stderr)


def _print_guidelines_footer(radon_available: bool) -> None:
    """Print guidelines footer with standards reference."""
    print("Guidelines (see .agent/standards/CODE-PATTERNS.md):", file=sys.stderr)
    print("  - SIZE-001: Files should be under 500 lines", file=sys.stderr)
    print("  - SIZE-002: Functions should be under 100 lines", file=sys.stderr)
    if radon_available:
        print(
            "  - Cyclomatic complexity should be <= 10 (fewer branches)",
            file=sys.stderr,
        )
        print(
            "  - Maintainability Index should be >= 40 (higher is better)",
            file=sys.stderr,
        )
    print("\nPlease refactor these before committing.", file=sys.stderr)


def print_human_output(result: AnalysisResult, min_severity: Severity) -> None:
    """Print human-readable output to stderr."""
    violations = [v for v in result.get_sorted_violations() if v.severity <= min_severity]

    if not violations:
        _print_pass_message(result, min_severity)
        return

    summary = result.summary()
    _print_summary_header(violations, summary, min_severity)
    _print_violations_by_file(result, min_severity)
    _print_guidelines_footer(result.radon_available)


def print_json_output(result: AnalysisResult, min_severity: Severity) -> None:
    """Print JSON output for CI/agent consumption."""
    output = result.to_dict()
    violations = output["violations"]
    if isinstance(violations, list):
        output["violations"] = [
            v
            for v in violations
            if isinstance(v, dict)
            and SEVERITY_MAP.get(str(v.get("severity", "")), Severity.LOW) <= min_severity
        ]
    output["min_severity"] = min_severity.name.lower()
    output["radon_available"] = result.radon_available
    print(json.dumps(output, indent=2))


def get_files_to_check(args: list[str]) -> list[Path]:
    """Determine which files to check based on arguments."""
    file_args = [a for a in args if not a.startswith("--")]

    if file_args:
        return [Path(f) for f in file_args if Path(f).exists()]

    # No files specified -- scan standard directories
    python_files: list[Path] = []
    for base_dir in ["src", "services", "scripts"]:
        base_path = Path(base_dir)
        if base_path.exists():
            python_files.extend(base_path.rglob("*.py"))

    return python_files


def parse_args(args: list[str]) -> tuple[bool, Severity]:
    """Parse command line arguments.

    Returns:
        Tuple of (json_output, min_severity)
    """
    json_output = "--json" in args

    min_severity = Severity.MEDIUM  # Default: fail on MEDIUM and above
    for i, arg in enumerate(args):
        if arg == "--min-severity" and i + 1 < len(args):
            severity_name = args[i + 1].lower()
            if severity_name in SEVERITY_MAP:
                min_severity = SEVERITY_MAP[severity_name]

    return json_output, min_severity


def main() -> int:
    """Main entry point for complexity analysis."""
    args = sys.argv[1:]
    json_output, min_severity = parse_args(args)

    analyzer = CodeAnalyzer(
        thresholds=Thresholds(),
        exclude_files=EXEMPT_FILES,
    )

    files = get_files_to_check(args)
    if not files:
        if json_output:
            print(json.dumps({"total_files": 0, "violations": []}))
        else:
            print("No Python files to check", file=sys.stderr)
        return 0

    files_to_check = [f for f in files if analyzer.should_check_file(f)]
    result = analyzer.analyze_files(files_to_check)

    if json_output:
        print_json_output(result, min_severity)
    else:
        print_human_output(result, min_severity)

    violations_at_level = [v for v in result.violations if v.severity <= min_severity]
    return 1 if violations_at_level else 0


if __name__ == "__main__":
    sys.exit(main())
