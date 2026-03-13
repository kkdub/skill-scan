"""Pattern rule definitions and loading for check_code_patterns.

Owns the heuristic-to-regex mapping table, the Pattern dataclass,
and the JSON-to-Pattern loader.  Extracted from check_code_patterns.py
to keep each module under the 300-line limit.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# Context check types
CONTEXT_CHECK_TRY_EXCEPT = "try_except"


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
    context_check: str | None = None
    context_exception: str | None = None


@dataclass(slots=True, frozen=True)
class HeuristicMapping:
    """Mapping from heuristic to regex with optional context checking."""

    regex: str
    context_check: str | None = None
    context_exception: str | None = None


def _build_antipattern_mappings() -> dict[str, HeuristicMapping]:
    """Build mappings for ANTI-* rules."""
    return {
        # ANTI-001: Mutable default arguments
        "Default value is [], {}, or set()": HeuristicMapping(
            r"def\s+\w+\([^)]*(?::\s*list\s*=\s*\[\]|:\s*dict\s*=\s*\{\}|:\s*set\s*=\s*set\(\))"
        ),
        # ANTI-003: Global mutable state
        "global keyword followed by assignment": HeuristicMapping(r"^\s*global\s+\w+"),
        # ANTI-004: Fire-and-forget tasks
        "create_task without storing reference": HeuristicMapping(
            r"^\s*(?:asyncio\.)?create_task\([^)]+\)\s*$"
        ),
        # ANTI-005: Using type() instead of isinstance()
        "type(x) == or type(x) is": HeuristicMapping(r"type\([^)]+\)\s*(?:==|is)\s"),
        # ANTI-006: Complex lambdas
        "Lambda with multiple method calls or conditionals": HeuristicMapping(
            r"lambda[^:]+:.*(?:\bif\b|\belse\b|\.[^.]+\.[^.]+\.)"
        ),
        # ANTI-007: String concatenation in loop (single-line form only;
        # multi-line loop bodies need AST analysis — see check_ast_antipatterns)
        "+= in loop with string": HeuristicMapping(
            r"(?:for\s+\w+\s+in\s[^:\n]+|while\s[^:\n]+):[^\n]*\w+\s*\+=\s*(?:f?['\"])"
        ),
        # ANTI-008: Hardcoded paths
        "String starting with /home/ or /usr/": HeuristicMapping(r"['\"]\/(?:home|usr|tmp|var|etc)\/"),
        # ANTI-009: Unchecked JSON parsing
        "json.loads without try/except": HeuristicMapping(
            r"json\.loads\(",
            context_check=CONTEXT_CHECK_TRY_EXCEPT,
            context_exception="JSONDecodeError",
        ),
        # ANTI-010: Semaphore without context manager
        "semaphore.acquire() without async with": HeuristicMapping(r"\.acquire\(\)\s*$"),
    }


def _build_error_and_security_mappings() -> dict[str, HeuristicMapping]:
    """Build mappings for ERROR-* and SECURITY-* rules."""
    return {
        # ERROR-001: Bare except
        "except: without exception type": HeuristicMapping(r"^\s*except\s*:"),
        # ERROR-003: Swallowing exceptions
        "except Exception followed by pass/return None/continue": HeuristicMapping(
            r"except\s+(?:Exception|BaseException)\s*:.*(?:pass|return\s+None|continue)"
        ),
        # SECURITY-001: shell=True
        "subprocess.run/call/Popen with shell=True": HeuristicMapping(
            r"subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*True"
        ),
    }


def _build_type_and_style_mappings() -> dict[str, HeuristicMapping]:
    """Build mappings for TYPE-*, FILE-*, ASYNC-*, and STRUCTURE-* rules."""
    return {
        # STRUCTURE-003: Relative imports
        "from ..module or from . import in non-test code": HeuristicMapping(r"from\s+\.\.?\w*\s+import"),
        # TYPE-001: Optional/Union
        "from typing import Optional, Union": HeuristicMapping(
            r"from\s+typing\s+import\s+[^#\n]*\b(?:Optional|Union)\b"
        ),
        # TYPE-002: collections.abc
        "typing.Callable, typing.Mapping in imports": HeuristicMapping(
            r"(?:from\s+typing\s+import\s+[^#\n]*\b(?:Callable|Mapping|Sequence|Iterable|Iterator|MutableMapping|MutableSequence)\b|typing\.(?:Callable|Mapping|Sequence|Iterable|Iterator))"
        ),
        # TYPE-008: No bare type: ignore
        "New or modified line containing '# type: ignore' without a specific error code and justification": HeuristicMapping(
            r"#\s*type:\s*ignore(?!\[[^\]]+\][^\n]*#)"
        ),
        # FILE-001: Use pathlib
        "import os.path or os.path.join": HeuristicMapping(
            r"(?:import\s+os\.path|from\s+os\.path\s+import|os\.path\.(?:join|exists|isfile|isdir|dirname|basename))"
        ),
        # FILE-002: Use context managers
        "open() without with statement": HeuristicMapping(r"^\s*\w+\s*=\s*open\([^)]+\)\s*$"),
        # ASYNC-002: asyncio.timeout
        "asyncio.wait_for call": HeuristicMapping(r"asyncio\.wait_for\s*\("),
        # ASYNC-005: No time.sleep in async
        "time.sleep in async function": HeuristicMapping(r"time\.sleep\s*\("),
        # ASYNC-006: No blocking open() in async
        "open() call in async function": HeuristicMapping(
            r"(?:async\s+def[^:]+:(?:(?!\n(?:async )?def ).)*?[^a]open\()"
        ),
    }


_HEURISTIC_MAP: dict[str, HeuristicMapping] = {
    **_build_antipattern_mappings(),
    **_build_error_and_security_mappings(),
    **_build_type_and_style_mappings(),
}


def _heuristic_to_mapping(heuristic: str) -> HeuristicMapping | None:
    """Convert detectHeuristic description to regex pattern and context settings."""
    return _HEURISTIC_MAP.get(heuristic)


def load_patterns(patterns_file: Path) -> list[Pattern]:
    """Load pattern definitions from JSON rules file."""
    patterns: list[Pattern] = []

    with patterns_file.open(encoding="utf-8") as f:
        data = json.load(f)

    detectable_prefixes = ("ANTI-", "TYPE-", "FILE-", "ASYNC-", "ERROR-", "SECURITY-", "STRUCTURE-")

    rules = data.get("rules", {})
    for rule_id, rule in rules.items():
        if not any(rule_id.startswith(prefix) for prefix in detectable_prefixes):
            continue

        heuristic = rule.get("detectHeuristic", "")
        mapping = _heuristic_to_mapping(heuristic)

        if not mapping:
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
