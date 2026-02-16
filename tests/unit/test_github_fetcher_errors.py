"""Tests for GitHubFetcher error handling, auth, and file limits."""

from __future__ import annotations

import builtins
import os
import shutil
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx

from skill_scan._fetchers import GitHubFetcher
from skill_scan._github_api import FetchError, download_file
from skill_scan._github_api import validate_download_url, validate_entry_name
from tests.unit.github_fetcher_helpers import contents_response, file_item

_API_BASE = "https://api.github.com/repos"


@respx.mock
class TestGitHubFetcherHTTPErrors:
    """Tests for GitHub fetch HTTP error handling."""

    def test_404_raises_fetch_error(self) -> None:
        """404 response raises FetchError with descriptive message."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=httpx.Response(404),
        )
        fetcher = GitHubFetcher()
        with pytest.raises(FetchError, match="not found"):
            fetcher.fetch("owner/repo")
        assert fetcher.tmp_dir is None

    def test_403_raises_fetch_error(self) -> None:
        """403 response raises FetchError about rate limiting."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=httpx.Response(403),
        )
        fetcher = GitHubFetcher()
        with pytest.raises(FetchError, match="forbidden"):
            fetcher.fetch("owner/repo")

    def test_500_raises_fetch_error(self) -> None:
        """Server error raises FetchError."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=httpx.Response(500),
        )
        fetcher = GitHubFetcher()
        with pytest.raises(FetchError, match="API error 500"):
            fetcher.fetch("owner/repo")

    def test_cleanup_on_failure(self) -> None:
        """Temp directory is cleaned up when fetch fails."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=httpx.Response(404),
        )
        fetcher = GitHubFetcher()
        with pytest.raises(FetchError):
            fetcher.fetch("owner/repo")
        assert fetcher.tmp_dir is None


@respx.mock
class TestGitHubFetcherFileLimit:
    """Tests for FS-007 file count limit enforcement."""

    def test_exceeds_max_files_raises_fetch_error(self) -> None:
        """Exceeding max_files raises FetchError."""
        many_files = [file_item(f"file{i}.txt") for i in range(6)]
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response(many_files),
        )
        for i in range(5):
            respx.get(f"https://raw.githubusercontent.com/test/file{i}.txt").mock(
                return_value=httpx.Response(200, content=b"data"),
            )
        fetcher = GitHubFetcher(max_files=5)
        with pytest.raises(FetchError, match="file limit"):
            fetcher.fetch("owner/repo")

    def test_at_max_files_succeeds(self) -> None:
        """Exactly max_files does not raise."""
        files = [file_item(f"file{i}.txt") for i in range(3)]
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response(files),
        )
        for i in range(3):
            respx.get(f"https://raw.githubusercontent.com/test/file{i}.txt").mock(
                return_value=httpx.Response(200, content=b"data"),
            )
        fetcher = GitHubFetcher(max_files=3)
        try:
            result = fetcher.fetch("owner/repo")
            assert len(list(result.iterdir())) == 3
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
            return_value=httpx.Response(200, content=b"data"),
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
            return_value=httpx.Response(200, content=b"data"),
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


class TestValidateEntryName:
    """Tests for path traversal prevention in entry names."""

    def test_rejects_dotdot(self) -> None:
        with pytest.raises(FetchError, match="Unsafe entry name"):
            validate_entry_name("..")

    def test_rejects_dotdot_path(self) -> None:
        with pytest.raises(FetchError, match="Unsafe entry name"):
            validate_entry_name("../etc/passwd")

    def test_rejects_slash(self) -> None:
        with pytest.raises(FetchError, match="Unsafe entry name"):
            validate_entry_name("sub/file.txt")

    def test_rejects_backslash(self) -> None:
        with pytest.raises(FetchError, match="Unsafe entry name"):
            validate_entry_name("sub\\file.txt")

    def test_rejects_dot(self) -> None:
        with pytest.raises(FetchError, match="Unsafe entry name"):
            validate_entry_name(".")

    def test_rejects_empty(self) -> None:
        with pytest.raises(FetchError, match="Unsafe entry name"):
            validate_entry_name("")

    def test_accepts_normal_name(self) -> None:
        validate_entry_name("SKILL.md")
        assert True

    def test_accepts_double_dot_in_filename(self) -> None:
        """Filenames like 'file..txt' are legitimate and should be accepted."""
        validate_entry_name("file..txt")
        assert True


class TestValidateDownloadUrl:
    """Tests for SSRF prevention in download URLs."""

    def test_accepts_raw_githubusercontent(self) -> None:
        validate_download_url("https://raw.githubusercontent.com/owner/repo/main/file.md")
        assert True

    def test_rejects_attacker_host(self) -> None:
        with pytest.raises(FetchError, match="Untrusted download host"):
            validate_download_url("https://evil.com/payload")

    def test_rejects_http_scheme(self) -> None:
        """HTTP (non-HTTPS) URLs are rejected to prevent MitM attacks."""
        with pytest.raises(FetchError, match="Untrusted download scheme"):
            validate_download_url("http://raw.githubusercontent.com/owner/repo/main/file.md")

    def test_rejects_localhost(self) -> None:
        with pytest.raises(FetchError, match="Untrusted download scheme"):
            validate_download_url("http://localhost:8080/secret")


@respx.mock
class TestDownloadFileErrors:
    """Tests for download_file HTTP error handling."""

    def test_http_error_raises_fetch_error(self, tmp_path: Path) -> None:
        """HTTP errors during download raise FetchError."""
        url = "https://raw.githubusercontent.com/owner/repo/main/file.md"
        respx.get(url).mock(return_value=httpx.Response(404))
        dest = tmp_path / "file.md"
        with httpx.Client() as client:
            with pytest.raises(FetchError, match="HTTP 404"):
                download_file(client, url, dest)

    def test_success_writes_file(self, tmp_path: Path) -> None:
        """Successful download writes content to disk."""
        url = "https://raw.githubusercontent.com/owner/repo/main/file.md"
        respx.get(url).mock(return_value=httpx.Response(200, content=b"hello"))
        dest = tmp_path / "file.md"
        with httpx.Client() as client:
            download_file(client, url, dest)
        assert dest.read_bytes() == b"hello"


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
