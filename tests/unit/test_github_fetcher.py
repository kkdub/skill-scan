"""Tests for GitHubFetcher — remote skill fetching via GitHub Contents API."""

from __future__ import annotations

import shutil

import httpx
import pytest
import respx

from skill_scan._fetchers import GitHubFetcher, SkillFetcher
from skill_scan._github_api import parse_source
from tests.unit.github_fetcher_helpers import contents_response, dir_item, file_item

_API_BASE = "https://api.github.com/repos"


class TestParseSource:
    """Tests for the parse_source helper."""

    def test_owner_repo_without_ref(self) -> None:
        owner_repo, ref = parse_source("octocat/hello-world")
        assert owner_repo == "octocat/hello-world"
        assert ref is None

    def test_owner_repo_with_ref(self) -> None:
        owner_repo, ref = parse_source("octocat/hello-world@v1.0")
        assert owner_repo == "octocat/hello-world"
        assert ref == "v1.0"

    def test_owner_repo_with_branch_ref(self) -> None:
        owner_repo, ref = parse_source("octocat/hello-world@main")
        assert owner_repo == "octocat/hello-world"
        assert ref == "main"

    def test_invalid_format_no_slash(self) -> None:
        with pytest.raises(ValueError, match="expected 'owner/repo'"):
            parse_source("just-a-name")

    def test_invalid_format_empty_owner(self) -> None:
        with pytest.raises(ValueError, match="expected 'owner/repo'"):
            parse_source("/repo")

    def test_invalid_format_empty_repo(self) -> None:
        with pytest.raises(ValueError, match="expected 'owner/repo'"):
            parse_source("owner/")

    def test_invalid_format_empty_ref(self) -> None:
        with pytest.raises(ValueError, match="empty ref"):
            parse_source("owner/repo@")

    def test_ref_with_at_sign(self) -> None:
        """Ref containing @ splits at first @ after owner/repo."""
        owner_repo, ref = parse_source("owner/repo@feature@2")
        assert owner_repo == "owner/repo"
        assert ref == "feature@2"


class TestGitHubFetcherProtocol:
    """GitHubFetcher implements SkillFetcher protocol."""

    def test_is_skill_fetcher(self) -> None:
        fetcher = GitHubFetcher()
        assert isinstance(fetcher, SkillFetcher)


@respx.mock
class TestGitHubFetcherSuccess:
    """Tests for successful GitHub fetch operations."""

    def test_fetch_single_file(self) -> None:
        """Fetch a repo with a single file."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response([file_item("SKILL.md")]),
        )
        respx.get("https://raw.githubusercontent.com/test/SKILL.md").mock(
            return_value=httpx.Response(200, content=b"# Skill"),
        )
        fetcher = GitHubFetcher()
        try:
            result = fetcher.fetch("owner/repo")
            assert result.is_dir()
            assert (result / "SKILL.md").read_text() == "# Skill"
        finally:
            if fetcher.tmp_dir:
                shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)

    def test_fetch_with_ref(self) -> None:
        """Fetch passes ref as query param."""
        route = respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response([file_item("README.md")]),
        )
        respx.get("https://raw.githubusercontent.com/test/README.md").mock(
            return_value=httpx.Response(200, content=b"hello"),
        )
        fetcher = GitHubFetcher()
        try:
            fetcher.fetch("owner/repo@v2.0")
            assert route.called
            assert "ref=v2.0" in str(route.calls[0].request.url)
        finally:
            if fetcher.tmp_dir:
                shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)

    def test_fetch_nested_directory(self) -> None:
        """Fetch a repo with nested directories."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response([file_item("SKILL.md"), dir_item("src")]),
        )
        respx.get(f"{_API_BASE}/owner/repo/contents/src").mock(
            return_value=contents_response([file_item("main.py", "src")]),
        )
        respx.get("https://raw.githubusercontent.com/test/SKILL.md").mock(
            return_value=httpx.Response(200, content=b"# Skill"),
        )
        respx.get("https://raw.githubusercontent.com/test/src/main.py").mock(
            return_value=httpx.Response(200, content=b"print('hi')"),
        )
        fetcher = GitHubFetcher()
        try:
            result = fetcher.fetch("owner/repo")
            assert (result / "SKILL.md").exists()
            assert (result / "src" / "main.py").read_text() == "print('hi')"
        finally:
            if fetcher.tmp_dir:
                shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)

    def test_fetch_with_skill_path(self) -> None:
        """Fetch with skill_path fetches from subdirectory."""
        route = respx.get(f"{_API_BASE}/owner/repo/contents/skills/my-skill").mock(
            return_value=contents_response([file_item("SKILL.md", "skills/my-skill")]),
        )
        respx.get("https://raw.githubusercontent.com/test/skills/my-skill/SKILL.md").mock(
            return_value=httpx.Response(200, content=b"# Skill"),
        )
        fetcher = GitHubFetcher(skill_path="skills/my-skill")
        try:
            result = fetcher.fetch("owner/repo")
            assert route.called
            assert (result / "SKILL.md").exists()
        finally:
            if fetcher.tmp_dir:
                shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)

    def test_tmp_dir_property_set_after_fetch(self) -> None:
        """tmp_dir is set after fetch and exists."""
        respx.get(f"{_API_BASE}/owner/repo/contents/").mock(
            return_value=contents_response([file_item("SKILL.md")]),
        )
        respx.get("https://raw.githubusercontent.com/test/SKILL.md").mock(
            return_value=httpx.Response(200, content=b"data"),
        )
        fetcher = GitHubFetcher()
        assert fetcher.tmp_dir is None
        try:
            fetcher.fetch("owner/repo")
            assert fetcher.tmp_dir is not None
            assert fetcher.tmp_dir.exists()
        finally:
            if fetcher.tmp_dir:
                shutil.rmtree(fetcher.tmp_dir, ignore_errors=True)
