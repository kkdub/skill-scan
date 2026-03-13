"""Rule definitions and AST checks for the test-pattern pre-commit hook."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class Rule:
    """A single test pattern rule."""

    rule_id: str
    name: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    fix: str
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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

_STATUS_ALT = "|".join(sorted(HTTP_STATUS_CODES))

# ---------------------------------------------------------------------------
# Skip predicates
# ---------------------------------------------------------------------------


def _in_comment(line: str, _lines: list[str], _idx: int) -> bool:
    """Skip if the match is in a comment."""
    stripped = line.lstrip()
    return stripped.startswith("#")


def _is_conftest_or_fixture(_line: str, lines: list[str], idx: int) -> bool:
    """Skip test name checks for fixtures and conftest helpers."""
    return any("@pytest.fixture" in lines[i] for i in range(max(0, idx - 3), idx))


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: list[Rule] = []

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

# TEST-008: Patching the module under test
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

# ---------------------------------------------------------------------------
# TEST-010: assertion check (AST-based)
# ---------------------------------------------------------------------------

_TEST_010_RULE = Rule(
    rule_id="TEST-010",
    name="Test Without Assertions",
    severity="error",
    pattern=re.compile(""),
    message="Every test must have at least one assert or pytest.raises",
    fix="Add assert statements to verify behavior",
)


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


def _has_assertion(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if a function AST node contains any assertion."""
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            return True
        if isinstance(child, ast.With):
            for item in child.items:
                if _is_pytest_raises(item.context_expr):
                    return True
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Attribute) and func.attr.startswith("assert_"):
                return True
            if _is_pytest_raises(child):
                return True
    return False


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
