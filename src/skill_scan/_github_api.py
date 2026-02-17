"""GitHub API helpers for remote fetching.

Handles HTTP requests, URL validation, source parsing, and
authentication for the GitHub Contents API.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_ALLOWED_DOWNLOAD_HOSTS = frozenset({"raw.githubusercontent.com", "objects.githubusercontent.com"})
_MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


class FetchError(Exception):
    """Raised when a remote fetch operation fails."""


def validate_entry_name(name: str) -> None:
    """Reject path-traversal attempts in file/dir names from the API."""
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        msg = f"Unsafe entry name from API: {name!r}"
        raise FetchError(msg)


def validate_download_url(url: str) -> None:
    """Reject download URLs that are not HTTPS or not GitHub-owned hosts."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        msg = f"Untrusted download scheme: {parsed.scheme!r}"
        raise FetchError(msg)
    if parsed.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
        msg = f"Untrusted download host: {parsed.hostname}"
        raise FetchError(msg)


def import_httpx() -> Any:
    """Import httpx, raising a helpful error if not installed."""
    try:
        import httpx

        return httpx
    except ImportError:
        msg = "Install httpx for remote scanning: pip install skill-scan[remote]"
        raise ImportError(msg) from None


def parse_source(source: str) -> tuple[str, str | None]:
    """Parse 'owner/repo' or 'owner/repo@ref' into (owner/repo, ref)."""
    if "@" in source:
        repo_part, ref = source.split("@", 1)
        if not ref:
            msg = f"Invalid source format (empty ref): {source}"
            raise ValueError(msg)
    else:
        repo_part = source
        ref = None

    parts = repo_part.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        msg = f"Invalid source format, expected 'owner/repo': {source}"
        raise ValueError(msg)
    return repo_part, ref


def build_headers() -> dict[str, str]:
    """Build HTTP headers, including auth token if available."""
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def api_get(client: Any, url: str, params: dict[str, str]) -> Any:
    """Make a GET request to the GitHub API with error handling."""
    response = client.get(url, params=params)
    if response.status_code == 404:
        msg = f"Repository or path not found: {url}"
        raise FetchError(msg)
    if response.status_code == 403:
        msg = f"Access forbidden (rate limited or private repo): {url}"
        raise FetchError(msg)
    if response.status_code >= 400:
        msg = f"GitHub API error {response.status_code}: {url}"
        raise FetchError(msg)
    return response


def download_file(client: Any, url: str, dest: Path) -> None:
    """Download a file from a URL and write it to disk.

    Raises:
        FetchError: If the HTTP request fails or file exceeds size limit.
    """
    response = client.get(url)
    if response.status_code >= 400:
        msg = f"HTTP {response.status_code} downloading {url}"
        raise FetchError(msg)
    if len(response.content) > _MAX_DOWNLOAD_SIZE:
        msg = f"Download exceeds {_MAX_DOWNLOAD_SIZE} byte limit"
        raise FetchError(msg)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(response.content)
