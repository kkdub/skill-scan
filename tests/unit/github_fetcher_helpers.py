"""Shared test helpers for GitHub fetcher tests."""

from __future__ import annotations

import httpx


def contents_response(items: list[dict[str, str]]) -> httpx.Response:
    """Build a mock Contents API response."""
    return httpx.Response(200, json=items)


def file_item(name: str, path: str = "") -> dict[str, str]:
    """Build a file item as returned by GitHub Contents API."""
    full_path = f"{path}/{name}" if path else name
    return {
        "type": "file",
        "name": name,
        "path": full_path,
        "download_url": f"https://raw.githubusercontent.com/test/{full_path}",
    }


def dir_item(name: str, path: str = "") -> dict[str, str]:
    """Build a directory item as returned by GitHub Contents API."""
    full_path = f"{path}/{name}" if path else name
    return {"type": "dir", "name": name, "path": full_path}
