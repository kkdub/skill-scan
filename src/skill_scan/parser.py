"""SKILL.md frontmatter parser — stdlib only.

Extracts and validates YAML frontmatter from SKILL.md files.
Uses simple key: value parsing with no external dependencies.
"""

from __future__ import annotations

import re
from pathlib import Path

_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_NAME_MAX_LENGTH = 64
_DESCRIPTION_MAX_LENGTH = 1024
_REQUIRED_FIELDS = ("name", "description")
_FRONTMATTER_DELIMITER = "---"


class SkillParseError(Exception):
    """Raised when SKILL.md parsing or validation fails."""


def parse_skill_frontmatter(path: Path) -> dict[str, str]:
    """Parse and validate YAML frontmatter from a SKILL.md file.

    Args:
        path: Path to the skill directory (not the SKILL.md file itself).

    Returns:
        Dictionary of validated frontmatter key-value pairs.

    Raises:
        SkillParseError: If the file is missing, malformed, or fails validation.
    """
    skill_file = path / "SKILL.md"

    if not skill_file.exists():
        raise SkillParseError(f"SKILL.md not found in {path}")

    content = _read_skill_file(skill_file)
    raw_frontmatter = _extract_frontmatter(content)
    fields = _parse_fields(raw_frontmatter)
    _validate_required_fields(fields)
    _validate_name(fields["name"])
    _validate_description(fields["description"])

    return fields


def _read_skill_file(skill_file: Path) -> str:
    """Read SKILL.md content, handling encoding errors."""
    try:
        return skill_file.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise SkillParseError("Failed to read SKILL.md: invalid encoding") from e


def _extract_frontmatter(content: str) -> str:
    """Extract raw frontmatter text between --- delimiters.

    The opening --- must be on the very first line.
    """
    lines = content.split("\n")

    if not lines or lines[0].strip() != _FRONTMATTER_DELIMITER:
        raise SkillParseError("No frontmatter found in SKILL.md")

    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == _FRONTMATTER_DELIMITER:
            return "\n".join(lines[1:i])

    raise SkillParseError("Unterminated frontmatter in SKILL.md")


def _parse_fields(raw: str) -> dict[str, str]:
    """Parse simple key: value pairs from frontmatter text.

    Supports:
        - Simple key: value pairs (string values)
        - Quoted values (single and double quotes)
        - Comment lines starting with #
        - Empty lines (skipped)
    """
    fields: dict[str, str] = {}

    for line in raw.split("\n"):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        colon_pos = stripped.find(":")
        if colon_pos == -1:
            raise SkillParseError(f"Invalid frontmatter: expected 'key: value' but got {stripped[:100]!r}")

        key = stripped[:colon_pos].strip()
        value = stripped[colon_pos + 1 :].strip()

        if not key:
            raise SkillParseError(f"Invalid frontmatter: empty key in {stripped[:100]!r}")

        value = _unquote(value)
        fields[key] = value

    return fields


def _unquote(value: str) -> str:
    """Remove matching outer quotes (single or double) from a value."""
    if len(value) >= 2:
        if (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"):
            return value[1:-1]
    return value


def _validate_required_fields(fields: dict[str, str]) -> None:
    """Ensure all required fields are present."""
    for field in _REQUIRED_FIELDS:
        if field not in fields:
            raise SkillParseError(f"Missing required field: {field}")


def _validate_name(name: str) -> None:
    """Validate the skill name format.

    Rules:
        - 1-64 characters
        - Lowercase alphanumeric and hyphens only
        - No leading, trailing, or consecutive hyphens
    """
    if not name:
        raise SkillParseError("Invalid name: must not be empty")

    if len(name) > _NAME_MAX_LENGTH:
        raise SkillParseError(f"Invalid name: must be at most {_NAME_MAX_LENGTH} characters")

    if not _NAME_PATTERN.match(name):
        raise SkillParseError(
            "Invalid name: must be lowercase alphanumeric with hyphens,"
            " no leading/trailing/consecutive hyphens"
        )

    if "--" in name:
        raise SkillParseError("Invalid name: consecutive hyphens are not allowed")


def _validate_description(description: str) -> None:
    """Validate the skill description.

    Rules:
        - Non-empty after stripping whitespace
        - 1-1024 characters
    """
    stripped = description.strip()

    if not stripped:
        raise SkillParseError("Invalid description: must not be empty")

    if len(stripped) > _DESCRIPTION_MAX_LENGTH:
        raise SkillParseError(f"Invalid description: must be at most {_DESCRIPTION_MAX_LENGTH} characters")
