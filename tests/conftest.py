"""Shared test configuration and fixtures."""

from __future__ import annotations

from pathlib import Path


def make_skill_dir(
    tmp_path: Path,
    name: str = "test-skill",
    extra_files: dict[str, str] | None = None,
) -> Path:
    """Create a minimal skill directory for testing.

    Args:
        tmp_path: Base directory (usually pytest tmp_path fixture).
        name: Name of the skill.
        extra_files: Optional dict of filename -> content to add.

    Returns:
        Path to the created skill directory.
    """
    skill_dir = tmp_path / name
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A test skill.\n---\n",
        encoding="utf-8",
    )
    if extra_files:
        for fname, content in extra_files.items():
            (skill_dir / fname).write_text(content, encoding="utf-8")
    return skill_dir
