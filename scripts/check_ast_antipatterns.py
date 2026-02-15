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
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# Severity configuration for violation reporting
# Higher values indicate more severe issues that should be addressed first
SEVERITY_LEVELS = {"info": 1, "warning": 2, "error": 3}
SEVERITY_SYMBOLS = {"info": "[I]", "warning": "[W]", "error": "[E]"}

# Configurable thresholds for code quality checks
# These align with project standards in CLAUDE.md and CODE-PATTERNS.md
MAX_FUNCTION_LINES = 50  # SIZE-002: Functions should be concise and focused
MAX_ELIF_BRANCHES = 3  # CONTROL-001: Long chains should use match statements
MAX_INHERITANCE_DEPTH = 3  # INHERIT-002: Deep hierarchies indicate design issues

# Directories excluded from scanning (build artifacts, caches, dependencies)
EXCLUDE_DIRS = {".venv", "__pycache__", ".git", "node_modules", ".tox", ".mypy_cache"}

# Base classes that don't count toward inheritance depth
# These are abstract/protocol classes that define interfaces, not implementations
SKIP_BASE_CLASSES = {"ABC", "Protocol", "Generic", "TypedDict", "Enum", "Exception"}

# Methods that typically override parent class methods (from common frameworks)
# unittest: setUp, tearDown, setUpClass, tearDownClass
# Django views: get_queryset, get_context_data, form_valid, form_invalid
# General: run, execute, handle, process, validate, serialize, deserialize
COMMON_OVERRIDE_METHODS = {
    "setUp",
    "tearDown",
    "setUpClass",
    "tearDownClass",
    "run",
    "execute",
    "handle",
    "process",
    "validate",
    "serialize",
    "deserialize",
    "get_queryset",
    "get_context_data",
    "form_valid",
    "form_invalid",
}


@dataclass(frozen=True, slots=True)
class Violation:
    """A detected AST antipattern violation."""

    rule_id: str
    name: str
    file: Path
    line: int
    message: str
    severity: str


@dataclass(slots=True)
class Stats:
    """Violation statistics by severity."""

    errors: int = 0
    warnings: int = 0
    infos: int = 0

    def add(self, severity: str) -> None:
        """Increment counter for given severity."""
        match severity:
            case "error":
                self.errors += 1
            case "warning":
                self.warnings += 1
            case _:
                self.infos += 1


# -----------------------------------------------------------------------------
# AST Helper Functions
# These utilities extract information from AST nodes in a consistent way
# -----------------------------------------------------------------------------


def _get_decorator_name(decorator: ast.expr) -> str | None:
    """Extract the name from a decorator expression.

    Handles multiple decorator forms:
    - @decorator -> ast.Name
    - @decorator(...) -> ast.Call with ast.Name func
    - @module.decorator -> ast.Attribute
    - @module.decorator(...) -> ast.Call with ast.Attribute func
    """
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Call):
        func = decorator.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
    if isinstance(decorator, ast.Attribute):
        return decorator.attr
    return None


def _decorator_has_kwarg(decorator: ast.expr, name: str, value: object) -> bool:
    """Check if a Call decorator has a specific keyword argument value.

    Only works for decorators in call form: @decorator(key=value)
    Returns False for plain decorators without arguments.
    """
    if not isinstance(decorator, ast.Call):
        return False
    for kw in decorator.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value.value == value
    return False


def _get_node_end_line(node: ast.AST) -> int:
    """Get the last line number of an AST node.

    Walks all children to find the maximum end_lineno, which gives
    the true ending line of multi-line constructs like functions.
    """
    end_lineno = getattr(node, "end_lineno", None)
    lineno = getattr(node, "lineno", None)
    end_line: int = end_lineno if end_lineno is not None else (lineno if lineno is not None else 0)
    for child in ast.walk(node):
        child_end = getattr(child, "end_lineno", None)
        if child_end is not None:
            end_line = max(end_line, child_end)
    return end_line


def _extract_base_class_names(bases: list[ast.expr]) -> list[str]:
    """Extract class names from base class AST expressions.

    Handles both simple names (Parent) and attribute access (module.Parent).
    """
    names = []
    for base in bases:
        if isinstance(base, ast.Name):
            names.append(base.id)
        elif isinstance(base, ast.Attribute):
            names.append(base.attr)
    return names


# -----------------------------------------------------------------------------
# AST Visitor for Antipattern Detection
# Walks the AST and applies each check at the appropriate node type
# -----------------------------------------------------------------------------


class AntipatternVisitor(ast.NodeVisitor):
    """Visit AST nodes and collect antipattern violations.

    Uses the visitor pattern to walk the AST and apply targeted checks
    at each node type. Maintains context about the current class being
    visited to enable method-level checks that need class information.
    """

    def __init__(self, filepath: Path) -> None:
        self.filepath = filepath
        self.violations: list[Violation] = []
        # Track current class context for method checks
        self._current_class: str | None = None
        # Map class names to their base class names for inheritance checks
        self._class_bases: dict[str, list[str]] = {}
        # Track visited if nodes to avoid double-counting elif chains
        self._visited_ifs: set[int] = set()

    def _add_violation(
        self, rule_id: str, name: str, line: int, message: str, severity: str = "info"
    ) -> None:
        """Add a violation to the list."""
        self.violations.append(Violation(rule_id, name, self.filepath, line, message, severity))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Check class definitions for DATA-001 and INHERIT-002."""
        base_names = _extract_base_class_names(node.bases)
        self._class_bases[node.name] = base_names

        self._check_dataclass_slots(node)
        self._check_inheritance_depth(node, base_names)

        # Visit methods with class context
        prev_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev_class

    def _check_dataclass_slots(self, node: ast.ClassDef) -> None:
        """DATA-001: Check if dataclass has slots=True."""
        for decorator in node.decorator_list:
            if _get_decorator_name(decorator) != "dataclass":
                continue
            # Plain @dataclass without arguments lacks slots
            if isinstance(decorator, ast.Name):
                self._add_violation(
                    "DATA-001",
                    "Dataclass without slots",
                    node.lineno,
                    f"Class '{node.name}': use @dataclass(slots=True)",
                )
            # @dataclass(...) needs slots=True
            elif not _decorator_has_kwarg(decorator, "slots", True):
                self._add_violation(
                    "DATA-001",
                    "Dataclass without slots",
                    node.lineno,
                    f"Class '{node.name}': use @dataclass(slots=True)",
                )
            break

    def _check_inheritance_depth(self, node: ast.ClassDef, base_names: list[str]) -> None:
        """INHERIT-002: Check for deep inheritance hierarchy."""
        meaningful_bases = [b for b in base_names if b not in SKIP_BASE_CLASSES]
        if len(meaningful_bases) >= MAX_INHERITANCE_DEPTH:
            self._add_violation(
                "INHERIT-002",
                "Deep inheritance",
                node.lineno,
                f"'{node.name}': {len(meaningful_bases)} bases, prefer composition",
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function definitions for antipatterns."""
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Check async function definitions for antipatterns."""
        self._check_function(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Check SIZE-002, TYPE-003, INHERIT-001 for a function."""
        self._check_function_size(node)
        self._check_self_return_type(node)
        self._check_override_decorator(node)
        self.generic_visit(node)

    def _check_function_size(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """SIZE-002: Check if function exceeds line limit."""
        if not node.body:
            return
        line_count = _get_node_end_line(node) - node.lineno + 1
        if line_count > MAX_FUNCTION_LINES:
            self._add_violation(
                "SIZE-002",
                "Function too long",
                node.lineno,
                f"'{node.name}': {line_count} lines (max {MAX_FUNCTION_LINES})",
                "warning",
            )

    def _check_self_return_type(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """TYPE-003: Check if method returns class name instead of Self."""
        if self._current_class is None or node.returns is None:
            return
        ret = node.returns
        class_name = self._current_class
        is_string_ref = isinstance(ret, ast.Constant) and ret.value == class_name
        is_name_ref = isinstance(ret, ast.Name) and ret.id == class_name
        if is_string_ref or is_name_ref:
            self._add_violation(
                "TYPE-003",
                "Use Self type",
                node.lineno,
                f"Use 'Self' instead of '{class_name}' for return type",
            )

    def _check_override_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """INHERIT-001: Check if overriding method has @override decorator."""
        # Skip if not in a class or is a dunder method
        if self._current_class is None:
            return
        if node.name.startswith("__") and node.name.endswith("__"):
            return
        # Skip if class has no bases (nothing to override)
        if not self._class_bases.get(self._current_class):
            return
        # Check for common override methods without @override
        if node.name not in COMMON_OVERRIDE_METHODS:
            return
        has_override = any(_get_decorator_name(d) == "override" for d in node.decorator_list)
        if not has_override:
            self._add_violation(
                "INHERIT-001",
                "Missing @override",
                node.lineno,
                f"Method '{node.name}' overrides parent - add @override",
            )

    def visit_If(self, node: ast.If) -> None:
        """CONTROL-001: Check for long elif chains."""
        if id(node) not in self._visited_ifs:
            self._check_elif_chain(node)
        self.generic_visit(node)

    def _check_elif_chain(self, node: ast.If) -> None:
        """Count elif branches and report if exceeds threshold."""
        elif_count = 0
        current: ast.If | None = node
        while current is not None:
            self._visited_ifs.add(id(current))
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                elif_count += 1
                current = current.orelse[0]
            else:
                current = None
        if elif_count >= MAX_ELIF_BRANCHES:
            self._add_violation(
                "CONTROL-001",
                "Consider match",
                node.lineno,
                f"{elif_count} elif branches - consider match statement",
            )


# -----------------------------------------------------------------------------
# File Discovery and Processing
# Handles walking directories and parsing individual Python files
# -----------------------------------------------------------------------------


def walk_python_files(root: Path) -> Iterator[Path]:
    """Yield Python files, skipping excluded directories.

    Recursively walks the directory tree and yields .py files,
    excluding common non-source directories like .venv and __pycache__.
    """
    for path in root.rglob("*.py"):
        if not any(excl in path.parts for excl in EXCLUDE_DIRS):
            yield path


def check_file(file_path: Path) -> list[Violation]:
    """Check a single file for AST antipattern violations.

    Reads the file, parses it into an AST, and runs all antipattern
    checks via the visitor. Returns empty list on read/parse errors.
    """
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
    except (OSError, UnicodeDecodeError, SyntaxError) as e:
        print(f"Warning: Could not process {file_path}: {e}", file=sys.stderr)
        return []

    visitor = AntipatternVisitor(file_path)
    visitor.visit(tree)
    return visitor.violations


# -----------------------------------------------------------------------------
# Output Formatting and CLI
# Handles violation display and command-line argument parsing
# -----------------------------------------------------------------------------


def format_violation(v: Violation, verbose: bool = False) -> str:
    """Format a violation for display.

    In normal mode, shows a single-line summary.
    In verbose mode, shows a detailed multi-line report with rule info.
    """
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
