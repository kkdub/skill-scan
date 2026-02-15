"""Rule loading from TOML files — file I/O and parsing.

Reads TOML rule definitions and compiles them into Rule objects
with pre-compiled regex patterns for efficient matching.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from skill_scan.models import Rule, Severity

_FLAG_MAP: dict[str, re.RegexFlag] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


def load_rules(path: Path) -> list[Rule]:
    """Load rules from a single TOML file.

    The TOML file must contain a [rules] table where each key is a rule ID
    and the value is a table with rule configuration fields.

    Args:
        path: Path to the TOML rule file.

    Returns:
        List of Rule objects sorted by rule_id.

    Raises:
        FileNotFoundError: If the TOML file does not exist.
        tomllib.TOMLDecodeError: If the TOML is malformed.
        KeyError: If required fields are missing from a rule definition.
        ValueError: If severity string is not a valid Severity enum value.
    """
    with path.open("rb") as f:
        data = tomllib.load(f)

    rules_table: dict[str, dict[str, object]] = data.get("rules", {})
    rules = [_parse_rule(rule_id, config) for rule_id, config in rules_table.items()]
    rules.sort(key=lambda r: r.rule_id)
    return rules


def load_default_rules() -> list[Rule]:
    """Discover and load all TOML rule files from the built-in data directory.

    Scans the ``rules/data/`` directory (relative to this package) for
    ``*.toml`` files and loads all rules from them.

    Returns:
        List of Rule objects sorted by rule_id, aggregated from all files.
    """
    data_dir = Path(__file__).parent / "data"
    all_rules: list[Rule] = []

    for toml_path in sorted(data_dir.glob("*.toml")):
        all_rules.extend(load_rules(toml_path))

    all_rules.sort(key=lambda r: r.rule_id)
    return all_rules


def _parse_rule(rule_id: str, config: dict[str, object]) -> Rule:
    """Parse a single rule definition into a Rule object."""
    severity = Severity(config["severity"])
    flags = _parse_flags(config.get("flags"))

    patterns = _compile_patterns(config.get("patterns", []), flags)
    exclude_patterns = _compile_patterns(config.get("exclude_patterns", []), flags)

    return Rule(
        rule_id=rule_id,
        severity=severity,
        category=str(config["category"]),
        description=str(config["description"]),
        recommendation=str(config["recommendation"]),
        patterns=patterns,
        exclude_patterns=exclude_patterns,
    )


def _parse_flags(flags_value: object) -> re.RegexFlag:
    """Parse a flags string into combined re.RegexFlag.

    Supports comma-separated or pipe-separated flag names:
    ``"IGNORECASE"``, ``"IGNORECASE|MULTILINE"``, ``"IGNORECASE,MULTILINE"``

    Returns ``re.RegexFlag(0)`` if flags_value is None or empty.
    """
    if not flags_value:
        return re.RegexFlag(0)

    raw = str(flags_value)
    combined = re.RegexFlag(0)

    for part in re.split(r"[|,]", raw):
        name = part.strip()
        if name:
            flag = _FLAG_MAP.get(name)
            if flag is None:
                msg = f"Unknown regex flag: {name}"
                raise ValueError(msg)
            combined |= flag

    return combined


def _compile_patterns(
    raw_patterns: object,
    flags: re.RegexFlag,
) -> tuple[re.Pattern[str], ...]:
    """Compile a list of pattern strings into regex Pattern objects."""
    if not isinstance(raw_patterns, list):
        return ()

    compiled: list[re.Pattern[str]] = []
    for pattern_str in raw_patterns:
        try:
            compiled.append(re.compile(str(pattern_str), flags))
        except re.error as e:
            msg = f"Invalid regex pattern {pattern_str!r}: {e}"
            raise ValueError(msg) from e

    return tuple(compiled)
