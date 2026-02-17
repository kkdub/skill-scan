"""Tests for _github_api.py — validation, download, and utility functions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx

from skill_scan._github_api import FetchError, download_file
from skill_scan._github_api import validate_download_url, validate_entry_name
from tests.constants import HTTP_NOT_FOUND, HTTP_OK


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


class TestDownloadFile:
    """Tests for download_file HTTP and size limit handling."""

    @respx.mock
    def test_http_error_raises_fetch_error(self, tmp_path: Path) -> None:
        """HTTP errors during download raise FetchError."""
        url = "https://raw.githubusercontent.com/owner/repo/main/file.md"
        respx.get(url).mock(return_value=httpx.Response(HTTP_NOT_FOUND))
        dest = tmp_path / "file.md"
        with httpx.Client() as client:
            with pytest.raises(FetchError, match="HTTP 404"):
                download_file(client, url, dest)

    @respx.mock
    def test_success_writes_file(self, tmp_path: Path) -> None:
        """Successful download writes content to disk."""
        url = "https://raw.githubusercontent.com/owner/repo/main/file.md"
        respx.get(url).mock(return_value=httpx.Response(HTTP_OK, content=b"hello"))
        dest = tmp_path / "file.md"
        with httpx.Client() as client:
            download_file(client, url, dest)
        assert dest.read_bytes() == b"hello"

    @respx.mock
    def test_oversized_download_raises_fetch_error(self, tmp_path: Path) -> None:
        """Download exceeding size limit raises FetchError."""
        url = "https://raw.githubusercontent.com/owner/repo/main/big.bin"
        with patch("skill_scan._github_api._MAX_DOWNLOAD_SIZE", 100):
            respx.get(url).mock(
                return_value=httpx.Response(HTTP_OK, content=b"x" * 101),
            )
            dest = tmp_path / "big.bin"
            with httpx.Client() as client:
                with pytest.raises(FetchError, match="byte limit"):
                    download_file(client, url, dest)
