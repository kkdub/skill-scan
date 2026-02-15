"""Tests for SKILL.md frontmatter parser."""

from pathlib import Path

import pytest

from skill_scan.parser import SkillParseError, parse_skill_frontmatter

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "skills"


@pytest.mark.parametrize(
    ("fixture_name", "expected_name", "expected_desc"),
    [
        ("valid-skill", "valid-skill", "A valid test skill for unit testing."),
        ("empty-skill", "empty-skill", "An empty skill with only frontmatter."),
    ],
)
def test_parse_skill_frontmatter_parses_valid_fixtures(
    fixture_name: str,
    expected_name: str,
    expected_desc: str,
) -> None:
    """Parse valid fixture files returns correct fields."""
    result = parse_skill_frontmatter(FIXTURES_DIR / fixture_name)

    assert result["name"] == expected_name
    assert result["description"] == expected_desc


@pytest.mark.parametrize(
    ("content", "expected_name", "expected_desc"),
    [
        (
            '---\nname: test-skill\ndescription: "A quoted description."\n---\n',
            "test-skill",
            "A quoted description.",
        ),
        (
            "---\nname: test-skill\ndescription: 'A quoted description.'\n---\n",
            "test-skill",
            "A quoted description.",
        ),
        (
            "---\n# Comment\nname: test-skill\n# Another\ndescription: Test.\n---\n",
            "test-skill",
            "Test.",
        ),
        (
            "---\n\nname: test-skill\n\ndescription: Test.\n\n---\n",
            "test-skill",
            "Test.",
        ),
    ],
)
def test_parse_skill_frontmatter_handles_special_formatting(
    tmp_path: Path,
    content: str,
    expected_name: str,
    expected_desc: str,
) -> None:
    """Parser correctly handles quoted values, comments, and empty lines."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(content, encoding="utf-8")

    result = parse_skill_frontmatter(tmp_path)

    assert result["name"] == expected_name
    assert result["description"] == expected_desc


def test_parse_skill_frontmatter_preserves_extra_fields(tmp_path: Path) -> None:
    """Extra fields beyond required ones are preserved."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        "---\nname: test-skill\ndescription: Test.\nversion: 1.0.0\nauthor: test\n---\n",
        encoding="utf-8",
    )

    result = parse_skill_frontmatter(tmp_path)

    assert result["name"] == "test-skill"
    assert result["description"] == "Test."
    assert result["version"] == "1.0.0"
    assert result["author"] == "test"


def test_parse_skill_frontmatter_raises_when_skill_md_not_found(tmp_path: Path) -> None:
    """Directory with no SKILL.md raises SkillParseError."""
    with pytest.raises(SkillParseError, match="SKILL.md not found"):
        parse_skill_frontmatter(tmp_path)


def test_parse_skill_frontmatter_raises_when_no_frontmatter_delimiters() -> None:
    """Missing frontmatter (no ---) raises SkillParseError."""
    with pytest.raises(SkillParseError, match="No frontmatter found"):
        parse_skill_frontmatter(FIXTURES_DIR / "missing-frontmatter")


@pytest.mark.parametrize(
    ("content", "error_pattern"),
    [
        ("---\nname: test-skill\ndescription: Test.\n", "Unterminated frontmatter"),
        ("\n---\nname: test-skill\ndescription: Test.\n---\n", "No frontmatter found"),
    ],
)
def test_parse_skill_frontmatter_raises_on_malformed_frontmatter(
    tmp_path: Path,
    content: str,
    error_pattern: str,
) -> None:
    """Malformed frontmatter raises SkillParseError."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(content, encoding="utf-8")

    with pytest.raises(SkillParseError, match=error_pattern):
        parse_skill_frontmatter(tmp_path)


def test_parse_skill_frontmatter_raises_when_missing_description() -> None:
    """Missing description raises SkillParseError."""
    with pytest.raises(SkillParseError, match="Missing required field: description"):
        parse_skill_frontmatter(FIXTURES_DIR / "missing-fields")


@pytest.mark.parametrize(
    ("content", "field_name"),
    [
        ("---\nname: test-skill\n---\n", "description"),
        ("---\ndescription: Test.\n---\n", "name"),
    ],
)
def test_parse_skill_frontmatter_raises_when_required_field_missing(
    tmp_path: Path,
    content: str,
    field_name: str,
) -> None:
    """Missing required field raises SkillParseError with field name."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(content, encoding="utf-8")

    with pytest.raises(SkillParseError, match=f"Missing required field: {field_name}"):
        parse_skill_frontmatter(tmp_path)


def test_parse_skill_frontmatter_raises_when_name_has_uppercase() -> None:
    """Invalid name format (uppercase) raises SkillParseError."""
    with pytest.raises(SkillParseError, match="Invalid name"):
        parse_skill_frontmatter(FIXTURES_DIR / "invalid-schema")


@pytest.mark.parametrize(
    ("name", "error_pattern"),
    [
        ("", "must not be empty"),
        ("a" * 65, "must be at most 64 characters"),
        ("Test-Skill", "must be lowercase alphanumeric"),
        ("test_skill", "must be lowercase alphanumeric"),
        ("-test", "no leading/trailing/consecutive hyphens"),
        ("test-", "no leading/trailing/consecutive hyphens"),
        ("test--skill", "consecutive hyphens"),
        ("test skill", "must be lowercase alphanumeric"),
        ("test.skill", "must be lowercase alphanumeric"),
    ],
)
def test_parse_skill_frontmatter_raises_when_name_invalid(
    tmp_path: Path,
    name: str,
    error_pattern: str,
) -> None:
    """Invalid name formats raise SkillParseError with specific messages."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        f"---\nname: {name}\ndescription: Test.\n---\n",
        encoding="utf-8",
    )

    with pytest.raises(SkillParseError, match=error_pattern):
        parse_skill_frontmatter(tmp_path)


@pytest.mark.parametrize(
    ("description", "error_pattern"),
    [
        ("", "must not be empty"),
        ("   ", "must not be empty"),
        ("a" * 1025, "must be at most 1024 characters"),
    ],
)
def test_parse_skill_frontmatter_raises_when_description_invalid(
    tmp_path: Path,
    description: str,
    error_pattern: str,
) -> None:
    """Invalid description values raise SkillParseError with specific messages."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        f'---\nname: test-skill\ndescription: "{description}"\n---\n',
        encoding="utf-8",
    )

    with pytest.raises(SkillParseError, match=error_pattern):
        parse_skill_frontmatter(tmp_path)


def test_parse_skill_frontmatter_raises_when_invalid_encoding(tmp_path: Path) -> None:
    """UnicodeDecodeError raises SkillParseError with encoding message."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_bytes(b"\xff\xfe---\nname: test\n---\n")

    with pytest.raises(SkillParseError, match="invalid encoding"):
        parse_skill_frontmatter(tmp_path)


@pytest.mark.parametrize(
    ("name", "description"),
    [
        ("a" * 64, "Test."),  # Max length name
        ("a", "a" * 1024),  # Min length name, max length description
        ("my-test-skill-v2", "Test."),  # Valid hyphens
    ],
)
def test_parse_skill_frontmatter_accepts_valid_boundary_values(
    tmp_path: Path,
    name: str,
    description: str,
) -> None:
    """Valid boundary values for name and description are accepted."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n",
        encoding="utf-8",
    )

    result = parse_skill_frontmatter(tmp_path)

    assert result["name"] == name
    assert result["description"] == description
