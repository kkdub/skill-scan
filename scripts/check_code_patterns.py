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
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Add repo root to sys.path for imports when running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.antipattern_context import is_in_try_except_block

# Severity levels (higher = more severe)
SEVERITY_LEVELS = {"info": 1, "warning": 2, "error": 3}
SEVERITY_SYMBOLS = {"info": "[I]", "warning": "[W]", "error": "[E]"}

# Context check types
CONTEXT_CHECK_TRY_EXCEPT = "try_except"


_NOQA_RE = re.compile(r"#\s*noqa(?::\s*([A-Z][\w,-]+))?")


@dataclass(slots=True, frozen=True)
class Pattern:
    """A single code pattern rule definition."""

    rule_id: str
    name: str
    regex: re.Pattern[str]
    severity: str
    description: str
    fix: str
    explanation: str
    context_check: str | None = None  # Type of context validation needed
    context_exception: str | None = None  # Exception type to look for in context


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


@dataclass(slots=True, frozen=True)
class HeuristicMapping:
    """Mapping from heuristic to regex with optional context checking."""

    regex: str
    context_check: str | None = None
    context_exception: str | None = None


def _heuristic_to_mapping(heuristic: str) -> HeuristicMapping | None:
    """Convert detectHeuristic description to regex pattern and context settings."""
    # Map common heuristic descriptions to regex patterns
    heuristic_map: dict[str, HeuristicMapping] = {
        # ANTI-001: Mutable default arguments
        "Default value is [], {}, or set()": HeuristicMapping(
            r"def\s+\w+\([^)]*(?::\s*list\s*=\s*\[\]|:\s*dict\s*=\s*\{\}|:\s*set\s*=\s*set\(\))"
        ),
        # ERROR-003: Swallowing exceptions
        "except Exception followed by pass/return None/continue": HeuristicMapping(
            r"except\s+(?:Exception|BaseException)\s*:.*(?:pass|return\s+None|continue)"
        ),
        # ANTI-003: Global mutable state
        "global keyword followed by assignment": HeuristicMapping(r"^\s*global\s+\w+"),
        # ANTI-004: Fire-and-forget tasks (create_task not assigned to variable)
        "create_task without storing reference": HeuristicMapping(
            r"^\s*(?:asyncio\.)?create_task\([^)]+\)\s*$"
        ),
        # ANTI-005: Using type() instead of isinstance()
        "type(x) == or type(x) is": HeuristicMapping(r"type\([^)]+\)\s*(?:==|is)\s"),
        # ANTI-006: Complex lambdas (with conditionals or chained calls)
        "Lambda with multiple method calls or conditionals": HeuristicMapping(
            r"lambda[^:]+:.*(?:\bif\b|\belse\b|\.[^.]+\.[^.]+\.)"
        ),
        # ANTI-007: String concatenation in loop
        "+= in loop with string": HeuristicMapping(r"(?:for|while)[^:]+:.*\w+\s*\+=\s*['\"]"),
        # ANTI-008: Hardcoded paths
        "String starting with /home/ or /usr/": HeuristicMapping(r"['\"]\/(?:home|usr|tmp|var|etc)\/"),
        # ANTI-009: Unchecked JSON parsing (uses context check for try/except)
        "json.loads without try/except": HeuristicMapping(
            r"json\.loads\(",
            context_check=CONTEXT_CHECK_TRY_EXCEPT,
            context_exception="JSONDecodeError",
        ),
        # ANTI-010: Semaphore without context manager
        "semaphore.acquire() without async with": HeuristicMapping(r"\.acquire\(\)\s*$"),
        # === ERROR PATTERNS ===
        # ERROR-001: Bare except catches KeyboardInterrupt and SystemExit
        "except: without exception type": HeuristicMapping(r"^\s*except\s*:"),
        # === SECURITY PATTERNS ===
        # SECURITY-001: shell=True enables command injection
        "subprocess.run/call/Popen with shell=True": HeuristicMapping(
            r"subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*True"
        ),
        # === STRUCTURE PATTERNS ===
        # STRUCTURE-003: Relative imports break when modules are moved
        "from ..module or from . import in non-test code": HeuristicMapping(r"from\s+\.\.?\w*\s+import"),
        # === TYPE PATTERNS ===
        # TYPE-001: Use X | None instead of Optional[X]
        "from typing import Optional, Union": HeuristicMapping(
            r"from\s+typing\s+import\s+[^#\n]*\b(?:Optional|Union)\b"
        ),
        # TYPE-002: Use collections.abc instead of typing for Callable, Mapping, etc.
        "typing.Callable, typing.Mapping in imports": HeuristicMapping(
            r"(?:from\s+typing\s+import\s+[^#\n]*\b(?:Callable|Mapping|Sequence|Iterable|Iterator|MutableMapping|MutableSequence)\b|typing\.(?:Callable|Mapping|Sequence|Iterable|Iterator))"
        ),
        # === FILE PATTERNS ===
        # FILE-001: Use pathlib instead of os.path
        "import os.path or os.path.join": HeuristicMapping(
            r"(?:import\s+os\.path|from\s+os\.path\s+import|os\.path\.(?:join|exists|isfile|isdir|dirname|basename))"
        ),
        # FILE-002: Use context managers for file operations
        # Detects: variable = open(...) without being in a with statement
        "open() without with statement": HeuristicMapping(r"^\s*\w+\s*=\s*open\([^)]+\)\s*$"),
        # === ASYNC PATTERNS ===
        # ASYNC-002: Use asyncio.timeout instead of wait_for
        "asyncio.wait_for call": HeuristicMapping(r"asyncio\.wait_for\s*\("),
        # ASYNC-005: No time.sleep in async functions
        "time.sleep in async function": HeuristicMapping(r"time\.sleep\s*\("),
        # ASYNC-006: No blocking open() in async functions
        "open() call in async function": HeuristicMapping(r"(?:async\s+def[^:]+:.*[^a]open\()"),
    }
    return heuristic_map.get(heuristic)


def load_patterns(patterns_file: Path) -> list[Pattern]:
    """Load pattern definitions from JSON rules file."""
    patterns: list[Pattern] = []

    with patterns_file.open(encoding="utf-8") as f:
        data = json.load(f)

    # Patterns we can detect programmatically
    detectable_prefixes = ("ANTI-", "TYPE-", "FILE-", "ASYNC-", "ERROR-", "SECURITY-", "STRUCTURE-")

    rules = data.get("rules", {})
    for rule_id, rule in rules.items():
        # Only process patterns we have regex mappings for
        if not any(rule_id.startswith(prefix) for prefix in detectable_prefixes):
            continue

        heuristic = rule.get("detectHeuristic", "")
        mapping = _heuristic_to_mapping(heuristic)

        if not mapping:
            # Can't convert this heuristic to regex, skip it
            continue

        try:
            patterns.append(
                Pattern(
                    rule_id=rule_id,
                    name=rule.get("name", rule_id),
                    regex=re.compile(mapping.regex, re.MULTILINE | re.DOTALL),
                    severity=rule.get("severity", "warning"),
                    description=rule.get("description", ""),
                    fix=rule.get("correctPattern", ""),
                    explanation=rule.get("ifThen", ""),
                    context_check=mapping.context_check,
                    context_exception=mapping.context_exception,
                ),
            )
        except re.error as e:
            print(
                f"Warning: Skipping invalid pattern {rule_id}: {e}",
                file=sys.stderr,
            )

    return patterns


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

            # Check for
            noqa_match = _NOQA_RE.search(line_content)
            if noqa_match:
                codes = noqa_match.group(1)
                if codes is None or pattern.rule_id in codes.split(","):
                    continue

            # Apply context-aware filtering if specified
            if pattern.context_check == CONTEXT_CHECK_TRY_EXCEPT and is_in_try_except_block(
                lines,
                line_num,
                pattern.context_exception,
            ):
                # This pattern is properly handled, skip it
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
    # Try relative to script location
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
        # Read from stdin (for piping from git, find, etc.)
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

    # Sort by severity (errors first), then by file and line
    def sort_key(v: Violation) -> tuple[int, Path, int]:
        return (-SEVERITY_LEVELS.get(v.pattern.severity, 0), v.file, v.line_num)

    for v in sorted(violations, key=sort_key):
        print(format_violation(v, verbose=verbose))

    print(f"\nSummary: {stats.errors} errors, {stats.warnings} warnings, {stats.infos} info")

    if not verbose:
        print("\nRun with --verbose for detailed fix suggestions.")

    # Determine exit code based on --fail-on
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
        return 0  # Nothing to check

    all_violations: list[Violation] = []
    for file_path in python_files:
        all_violations.extend(check_file(file_path, patterns))

    return _report_violations(all_violations, args.verbose, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
