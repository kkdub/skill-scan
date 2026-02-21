"""Tests for GitHubFetcher error handling, auth, and file limits."""

from __future__ import annotations

import builtins
import os
import shutil
import sys
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx

from skill_scan._fetchers import GitHubFetcher
from skill_scan._github_api import FetchError
from tests.constants import HTTP_FORBIDDEN, HTTP_INTERNAL_ERROR, HTTP_NOT_FOUND, HTTP_OK
from tests.unit.github_fetcher_helpers import contents_response, file_item

_API_BASE = "https://api.github.com/repos"


class TestGitHubFetcherHTTPErrors:
    """Tests for GitHub fetch HTTP error handling."""

    @respx.mock
    def test_404_raises_fetch_error(self) -> None:
        """404 response raises FetchError with descriptive message."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=httpx.Response(HTTP_NOT_FOUND),
        )
        fetcher = GitHubFetcher()
        with pytest.raises(FetchError, match="not found"):
            fetcher.fetch("owner/repo")
        assert fetcher.tmp_dir is None

    @respx.mock
    def test_403_raises_fetch_error(self) -> None:
        """403 response raises FetchError about rate limiting."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=httpx.Response(HTTP_FORBIDDEN),
        )
        fetcher = GitHubFetcher()
        with pytest.raises(FetchError, match="forbidden"):
            fetcher.fetch("owner/repo")

    @respx.mock
    def test_500_raises_fetch_error(self) -> None:
        """Server error raises FetchError."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=httpx.Response(HTTP_INTERNAL_ERROR),
        )
        fetcher = GitHubFetcher()
        with pytest.raises(FetchError, match="API error 500"):
            fetcher.fetch("owner/repo")


class TestGitHubFetcherManyFiles:
    """Verify the fetcher handles repos with many files (no hard limit)."""

    @respx.mock
    def test_many_files_downloaded_successfully(self) -> None:
        """Fetcher downloads all files without a hard file-count error."""
        many_files = [file_item(f"file{i}.txt") for i in range(150)]
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response(many_files),
        )
        for i in range(150):
            respx.get(f"https://raw.githubusercontent.com/test/file{i}.txt").mock(
                return_value=httpx.Response(HTTP_OK, content=b"data"),
            )
        fetcher = GitHubFetcher()
        try:
            result = fetcher.fetch("owner/repo")
            assert len(list(result.iterdir())) == 150
        finally:
            if fetcher.tmp_dir:
                shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)


class TestGitHubFetcherToken:
    """Tests for GITHUB_TOKEN authentication."""

    @respx.mock
    def test_uses_github_token_when_set(self) -> None:
        """Auth header is set when GITHUB_TOKEN env var exists."""
        route = respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response([file_item("SKILL.md")]),
        )
        respx.get("https://raw.githubusercontent.com/test/SKILL.md").mock(
            return_value=httpx.Response(HTTP_OK, content=b"data"),
        )
        fetcher = GitHubFetcher()
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test123"}):
            try:
                fetcher.fetch("owner/repo")
                request = route.calls[0].request
                assert request.headers["authorization"] == "Bearer ghp_test123"
            finally:
                if fetcher.tmp_dir:
                    shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)

    @respx.mock
    def test_no_auth_header_without_token(self) -> None:
        """No auth header when GITHUB_TOKEN is not set."""
        route = respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response([file_item("SKILL.md")]),
        )
        respx.get("https://raw.githubusercontent.com/test/SKILL.md").mock(
            return_value=httpx.Response(HTTP_OK, content=b"data"),
        )
        fetcher = GitHubFetcher()
        with patch.dict(os.environ, {}, clear=True):
            try:
                fetcher.fetch("owner/repo")
                request = route.calls[0].request
                assert "authorization" not in request.headers
            finally:
                if fetcher.tmp_dir:
                    shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)


class TestGitHubFetcherMissingHttpx:
    """Tests for missing httpx dependency."""

    def test_missing_httpx_raises_import_error(self) -> None:
        """Missing httpx gives helpful error message."""
        original_import = builtins.__import__

        def mock_import(name: str, *args: Any, **kwargs: Any) -> object:
            if name == "httpx":
                raise ImportError("No module named 'httpx'")
            return original_import(name, *args, **kwargs)

        fetcher = GitHubFetcher()
        # Remove httpx from sys.modules so import statement calls __import__
        saved = sys.modules.pop("httpx", None)
        try:
            with patch.object(builtins, "__import__", side_effect=mock_import):
                with pytest.raises(ImportError, match="pip install skill-scan\\[remote\\]"):
                    fetcher.fetch("owner/repo")
        finally:
            if saved is not None:
                sys.modules["httpx"] = saved
