"""Skill fetcher protocol and implementations.

Defines SkillFetcher protocol, LocalFetcher, and GitHubFetcher.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

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

_DEFAULT_MAX_FILES = 100


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

    def __init__(self, skill_path: str = "", max_files: int = _DEFAULT_MAX_FILES) -> None:
        self._skill_path = skill_path
        self._max_files = max_files
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
                self._fetch_dir(client, owner_repo, ref, self._skill_path, self._tmp_dir, 0)
        except Exception:
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
        file_count: int,
    ) -> int:
        """Recursively fetch directory contents. Returns updated file count."""
        url = f"https://api.github.com/repos/{owner_repo}/contents/{api_path}"
        params: dict[str, str] = {"ref": ref} if ref else {}

        items = api_get(client, url, params).json()
        if not isinstance(items, list):
            msg = f"Expected directory listing at '{api_path}', got a file"
            raise FetchError(msg)

        for item in items:
            file_count = self._process_item(client, owner_repo, ref, item, local_dir, file_count)
        return file_count

    def _process_item(
        self,
        client: Any,
        owner_repo: str,
        ref: str | None,
        item: dict[str, Any],
        local_dir: Path,
        file_count: int,
    ) -> int:
        """Process a single item from the Contents API response."""
        item_type = item.get("type", "")
        name = item.get("name", "")
        validate_entry_name(name)

        if item_type == "file":
            if file_count >= self._max_files:
                msg = f"Repository exceeds {self._max_files} file limit (FS-007)"
                raise FetchError(msg)
            download_url = item.get("download_url")
            if download_url:
                validate_download_url(download_url)
                download_file(client, download_url, local_dir / name)
                file_count += 1
        elif item_type == "dir":
            sub_dir = local_dir / name
            sub_dir.mkdir(parents=True, exist_ok=True)
            file_count = self._fetch_dir(
                client,
                owner_repo,
                ref,
                item.get("path", ""),
                sub_dir,
                file_count,
            )
        return file_count
