"""Skill fetcher protocol and implementations.

Defines a protocol for fetching skill directories and a local filesystem
implementation. Future fetchers (git, registry) can implement the same protocol.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class SkillFetcher(Protocol):
    """Protocol for fetching skill directories for scanning."""

    def fetch(self, source: str) -> Path:
        """Fetch a skill and return the local directory path.

        Args:
            source: Identifier for the skill (path, URL, repo, etc.)

        Returns:
            Path to the local directory containing the skill files.
        """
        ...


class LocalFetcher:
    """Fetches skills from local filesystem paths."""

    def fetch(self, source: str) -> Path:
        """Return the local path as a Path object.

        Args:
            source: Filesystem path to the skill directory.

        Returns:
            Resolved Path to the skill directory.

        Raises:
            FileNotFoundError: If the path does not exist.
            NotADirectoryError: If the path is not a directory.
        """
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Skill directory not found: {source}")
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {source}")
        return path
