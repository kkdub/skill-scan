"""Data models and constants for AST antipattern detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

SEVERITY_LEVELS = {"info": 1, "warning": 2, "error": 3}
SEVERITY_SYMBOLS = {"info": "[I]", "warning": "[W]", "error": "[E]"}

MAX_FUNCTION_LINES = 50
MAX_ELIF_BRANCHES = 3
MAX_INHERITANCE_DEPTH = 3

EXCLUDE_DIRS = {".venv", "__pycache__", ".git", "node_modules", ".tox", ".mypy_cache"}

SKIP_BASE_CLASSES = {"ABC", "Protocol", "Generic", "TypedDict", "Enum", "Exception"}

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
