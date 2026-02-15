"""Tests for skill fetchers."""

from pathlib import Path

import pytest

from skill_scan._fetchers import LocalFetcher, SkillFetcher


def test_local_fetcher_fetch_returns_path_for_valid_directory(tmp_path: Path) -> None:
    """LocalFetcher.fetch returns Path for a valid directory."""
    skill_dir = tmp_path / "test-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: test-skill\ndescription: Test.\n---\n",
        encoding="utf-8",
    )
    fetcher = LocalFetcher()

    result = fetcher.fetch(str(skill_dir))

    assert isinstance(result, Path)
    assert result == skill_dir


def test_local_fetcher_fetch_raises_when_path_not_found(tmp_path: Path) -> None:
    """LocalFetcher.fetch raises FileNotFoundError when path does not exist."""
    fetcher = LocalFetcher()
    nonexistent = str(tmp_path / "does-not-exist")

    with pytest.raises(FileNotFoundError, match="Skill directory not found"):
        fetcher.fetch(nonexistent)


def test_local_fetcher_fetch_raises_when_path_is_file(tmp_path: Path) -> None:
    """LocalFetcher.fetch raises NotADirectoryError when path is a file."""
    fetcher = LocalFetcher()
    file_path = tmp_path / "file.txt"
    file_path.write_text("test", encoding="utf-8")

    with pytest.raises(NotADirectoryError, match="Not a directory"):
        fetcher.fetch(str(file_path))


def test_local_fetcher_is_skill_fetcher_protocol() -> None:
    """LocalFetcher implements the SkillFetcher protocol."""
    fetcher = LocalFetcher()

    assert isinstance(fetcher, SkillFetcher)
