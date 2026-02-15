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

import ast
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# --- Rule definitions ---

HTTP_STATUS_CODES = {
    "100",
    "101",
    "200",
    "201",
    "202",
    "204",
    "301",
    "302",
    "304",
    "307",
    "308",
    "400",
    "401",
    "403",
    "404",
    "405",
    "409",
    "410",
    "422",
    "429",
    "500",
    "502",
    "503",
    "504",
}

# Build alternation like (?:200|201|204|301|...)
_STATUS_ALT = "|".join(sorted(HTTP_STATUS_CODES))

RULES: list[Rule] = []


@dataclass(slots=True, frozen=True)
class Rule:
    """A single test pattern rule."""

    rule_id: str
    name: str
    severity: str  # "error" or "warning"
    pattern: re.Pattern[str]
    message: str
    fix: str
    # If set, this callable receives (line, all_lines, line_idx) and returns
    # True if the match is a false positive that should be skipped.
    skip_if: Callable[[str, list[str], int], bool] | None = None


@dataclass(slots=True, frozen=True)
class Violation:
    """A detected violation."""

    file: Path
    line_num: int
    line_content: str
    rule: Rule


@dataclass(slots=True)
class FileContext:
    """Parsed context for a single test file."""

    path: Path
    lines: list[str] = field(default_factory=list)
    test_functions: list[tuple[int, str]] = field(default_factory=list)


# --- Skip predicates ---


def _in_comment(line: str, _lines: list[str], _idx: int) -> bool:
    """Skip if the match is in a comment."""
    stripped = line.lstrip()
    return stripped.startswith("#")


def _is_conftest_or_fixture(line: str, lines: list[str], idx: int) -> bool:
    """Skip test name checks for fixtures and conftest helpers."""
    # Look backwards for @pytest.fixture decorator
    for i in range(max(0, idx - 3), idx):
        if "@pytest.fixture" in lines[i]:
            return True
    return False


# --- Rule registration ---

# TEST-001: Magic HTTP status codes
RULES.append(
    Rule(
        rule_id="TEST-001",
        name="Magic HTTP Status Code",
        severity="error",
        pattern=re.compile(rf"\.status_code\s*==\s*({_STATUS_ALT})\b"),
        message="Use named constant from tests/constants.py instead of magic number",
        fix="from tests.constants import HTTP_OK; assert response.status_code == HTTP_OK",
        skip_if=_in_comment,
    ),
)

# TEST-002: Redundant @pytest.mark.asyncio
RULES.append(
    Rule(
        rule_id="TEST-002",
        name="Redundant @pytest.mark.asyncio",
        severity="error",
        pattern=re.compile(r"@pytest\.mark\.asyncio"),
        message="Remove decorator - asyncio_mode='auto' is configured",
        fix="Use plain 'async def test_...():' without the decorator",
        skip_if=_in_comment,
    ),
)

# TEST-003: time.sleep in tests
RULES.append(
    Rule(
        rule_id="TEST-003",
        name="time.sleep() in Test",
        severity="error",
        pattern=re.compile(r"\btime\.sleep\s*\("),
        message="Use time_machine.travel() instead of time.sleep()",
        fix="with time_machine.travel('2025-01-01 12:00:00', tick=False):",
        skip_if=_in_comment,
    ),
)

# TEST-004: Patching httpx internals
RULES.append(
    Rule(
        rule_id="TEST-004",
        name="Mock Patching httpx",
        severity="error",
        pattern=re.compile(r"@patch\(['\"].*httpx\.(AsyncClient|Client)"),
        message="Use @respx.mock instead of patching httpx internals",
        fix="@respx.mock + respx.get(url).mock(return_value=Response(200, json={...}))",
        skip_if=_in_comment,
    ),
)

# TEST-006: Broad pytest.raises(Exception)
RULES.append(
    Rule(
        rule_id="TEST-006",
        name="Broad pytest.raises(Exception)",
        severity="error",
        pattern=re.compile(r"pytest\.raises\s*\(\s*Exception\s*\)"),
        message="Use specific exception type with match string",
        fix="pytest.raises(ValueError, match='expected message')",
        skip_if=_in_comment,
    ),
)

# TEST-007: Vague test names
# Part 1: Single-word names like test_users, test_auth
RULES.append(
    Rule(
        rule_id="TEST-007",
        name="Vague Test Name",
        severity="warning",
        pattern=re.compile(r"^\s*(?:async\s+)?def\s+(test_[a-z]+)\s*\(", re.MULTILINE),
        message="Test name should describe behavior: test_<unit>_<behavior>_<condition>",
        fix="test_validate_user_returns_none_for_invalid_password",
        skip_if=_is_conftest_or_fixture,
    ),
)

# Part 2: Names ending with vague suffixes (test_users_works, test_auth_ok)
_VAGUE_SUFFIXES = r"_(works|ok|good|fine|correct|basic|simple|test)"
RULES.append(
    Rule(
        rule_id="TEST-007",
        name="Vague Test Name (suffix)",
        severity="warning",
        pattern=re.compile(
            rf"^\s*(?:async\s+)?def\s+(test_\w+{_VAGUE_SUFFIXES})\s*\(",
            re.MULTILINE,
        ),
        message="Vague suffix - name should describe specific behavior, not just 'works'",
        fix="test_validate_user_returns_none_for_invalid_password",
        skip_if=_is_conftest_or_fixture,
    ),
)

# TEST-008: Patching the module under test (heuristic: @patch targeting business-logic methods)
# Catches @patch("myapp.services.user_service.UserService.process") in test_user_service.py
# Excludes generic names like get/post/put/delete — too many false positives from
# database sessions, caches, and HTTP clients (HTTP already caught by TEST-004).
RULES.append(
    Rule(
        rule_id="TEST-008",
        name="Patching Code Under Test",
        severity="warning",
        pattern=re.compile(
            r"@patch\(['\"](?!.*httpx).*\."
            r"(fetch|save|create|update|process|execute|handle|submit|validate)\b"
        ),
        message="Mock dependencies, not the code under test. Inject via constructor.",
        fix="service = UserService(database=mock_db)  # Inject mock dependency",
        skip_if=_in_comment,
    ),
)


# --- TEST-010: assertion check (AST-based) ---

_TEST_010_RULE = Rule(
    rule_id="TEST-010",
    name="Test Without Assertions",
    severity="error",
    pattern=re.compile(""),
    message="Every test must have at least one assert or pytest.raises",
    fix="Add assert statements to verify behavior",
)


def _has_assertion(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if a function AST node contains any assertion."""
    for child in ast.walk(node):
        # assert x == y
        if isinstance(child, ast.Assert):
            return True
        # with pytest.raises(...):
        if isinstance(child, ast.With):
            for item in child.items:
                if _is_pytest_raises(item.context_expr):
                    return True
        # mock.assert_called_once(), mock.assert_called_with(...)
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Attribute) and func.attr.startswith("assert_"):
                return True
            if _is_pytest_raises(child):
                return True
    return False


def _is_pytest_raises(node: ast.expr) -> bool:
    """Check if an AST node is a pytest.raises(...) call."""
    if isinstance(node, ast.Call):
        node = node.func
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "raises"
        and isinstance(node.value, ast.Name)
        and node.value.id == "pytest"
    )


def check_missing_assertions(ctx: FileContext) -> list[Violation]:
    """Find test functions that have no assert statements using AST."""
    try:
        tree = ast.parse("\n".join(ctx.lines), filename=str(ctx.path))
    except SyntaxError:
        return []

    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if not node.name.startswith("test_"):
            continue
        if _has_assertion(node):
            continue
        line_idx = node.lineno - 1
        violations.append(
            Violation(
                file=ctx.path,
                line_num=node.lineno,
                line_content=ctx.lines[line_idx].strip() if line_idx < len(ctx.lines) else "",
                rule=_TEST_010_RULE,
            ),
        )
    return violations


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

    # Per-line rule checks
    for line_idx, line in enumerate(lines):
        for rule in RULES:
            if rule.pattern.search(line):
                # Check skip predicate
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

    # Structural checks
    ctx = FileContext(path=filepath, lines=lines)
    violations.extend(check_missing_assertions(ctx))

    return violations


def _print_report(violations: list[Violation]) -> int:
    """Print violation report and return exit code (1 if errors, 0 if warnings only)."""
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
