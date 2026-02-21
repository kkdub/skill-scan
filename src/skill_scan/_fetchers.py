"""Skill fetcher protocol and implementations.

Defines SkillFetcher protocol, LocalFetcher, and GitHubFetcher.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable  # Any: httpx is conditionally imported

from skill_scan._github_api import (
    FetchError,
    api_get,
    build_headers,
    download_file,
    import_httpx,
    parse_source,
    validate_download_url,
    validate_entry_name,
)


@runtime_checkable
class SkillFetcher(Protocol):
    """Protocol for fetching skill directories for scanning."""

    def fetch(self, source: str) -> Path: ...


class LocalFetcher:
    """Fetches skills from local filesystem paths."""

    def fetch(self, source: str) -> Path:
        """Return the local path, validating it exists and is a directory."""
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Skill directory not found: {source}")
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {source}")
        return path


class GitHubFetcher:
    """Fetches skills from GitHub via the Contents API."""

    def __init__(self, skill_path: str = "") -> None:
        self._skill_path = skill_path
        self._tmp_dir: Path | None = None

    @property
    def tmp_dir(self) -> Path | None:
        """The temporary directory created during fetch, for cleanup."""
        return self._tmp_dir

    def fetch(self, source: str) -> Path:
        """Fetch skill from GitHub. source: 'owner/repo' or 'owner/repo@ref'."""
        httpx = import_httpx()
        owner_repo, ref = parse_source(source)
        self._tmp_dir = Path(tempfile.mkdtemp(prefix="skill-scan-"))

        headers = build_headers()
        try:
            with httpx.Client(headers=headers, timeout=30.0) as client:
                self._fetch_dir(client, owner_repo, ref, self._skill_path, self._tmp_dir)
        except Exception:  # noqa: ERROR-003
            import shutil

            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None
            raise
        return self._tmp_dir

    def _fetch_dir(
        self,
        client: Any,
        owner_repo: str,
        ref: str | None,
        api_path: str,
        local_dir: Path,
    ) -> None:
        """Recursively fetch directory contents."""
        url = f"https://api.github.com/repos/{owner_repo}/contents/{api_path}"
        params: dict[str, str] = {"ref": ref} if ref else {}

        items = api_get(client, url, params).json()
        if not isinstance(items, list):
            msg = f"Expected directory listing at '{api_path}', got a file"
            raise FetchError(msg)

        for item in items:
            self._process_item(client, owner_repo, ref, item, local_dir)

    def _process_item(
        self,
        client: Any,
        owner_repo: str,
        ref: str | None,
        item: dict[str, Any],
        local_dir: Path,
    ) -> None:
        """Execute I/O for a single Contents API item."""
        action = _plan_item_action(item)
        if action is None:
            return
        kind, name, target = action
        if kind == "download":
            download_file(client, target, local_dir / name)
            return
        # kind == "recurse"
        sub_dir = local_dir / name
        sub_dir.mkdir(parents=True, exist_ok=True)
        self._fetch_dir(client, owner_repo, ref, target, sub_dir)


def _plan_item_action(item: dict[str, Any]) -> tuple[str, str, str] | None:
    """Decide what action to take for a GitHub Contents API item.

    Pure decision function — validates the item and determines the action
    without performing any I/O.

    Returns:
        ("download", name, url) for file items with a download URL.
        ("recurse", name, api_path) for directory items.
        None for unknown or no-op items.

    Raises:
        FetchError: If name validation fails.
    """
    name = item.get("name", "")
    validate_entry_name(name)
    item_type = item.get("type", "")

    if item_type == "file":
        download_url = item.get("download_url")
        if download_url:
            validate_download_url(download_url)
            return ("download", name, download_url)
        return None

    if item_type == "dir":
        return ("recurse", name, item.get("path", ""))

    return None
