"""Tests for Dockerfile and .dockerignore configuration."""

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = PROJECT_ROOT / "Dockerfile"
DOCKERIGNORE = PROJECT_ROOT / ".dockerignore"


@pytest.fixture()
def dockerfile_lines() -> list[str]:
    """Read Dockerfile lines as-is."""
    return DOCKERFILE.read_text().splitlines()


@pytest.fixture()
def dockerfile_instructions(dockerfile_lines: list[str]) -> list[str]:
    """Extract non-comment, non-empty Dockerfile instructions."""
    return [line for line in dockerfile_lines if line.strip() and not line.strip().startswith("#")]


@pytest.fixture()
def dockerignore_entries() -> list[str]:
    """Read .dockerignore entries, excluding comments and blanks."""
    return [
        line.strip()
        for line in DOCKERIGNORE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


# --- Dockerfile tests ---


class TestDockerfileBaseImage:
    """Tests for the Dockerfile base image configuration."""

    def test_dockerfile_exists(self) -> None:
        """Dockerfile exists at project root."""
        assert DOCKERFILE.is_file()

    def test_dockerfile_uses_python_313_slim(self, dockerfile_lines: list[str]) -> None:
        """Base image is python:3.13-slim."""
        from_lines = [line for line in dockerfile_lines if line.startswith("FROM ")]
        assert len(from_lines) == 1
        assert from_lines[0] == "FROM python:3.13-slim"


class TestDockerfileUser:
    """Tests for the non-root user configuration."""

    def test_dockerfile_creates_scanner_user(self, dockerfile_instructions: list[str]) -> None:
        """Dockerfile creates a 'scanner' system user."""
        run_lines = [line for line in dockerfile_instructions if line.startswith("RUN ")]
        user_creation = [line for line in run_lines if "useradd" in line and "scanner" in line]
        assert len(user_creation) == 1

    def test_dockerfile_sets_user_scanner(self, dockerfile_instructions: list[str]) -> None:
        """USER instruction sets the scanner user."""
        user_lines = [line for line in dockerfile_instructions if line.startswith("USER ")]
        assert len(user_lines) == 1
        assert user_lines[0] == "USER scanner"

    def test_dockerfile_user_after_install(self, dockerfile_instructions: list[str]) -> None:
        """USER instruction comes after pip install (install as root)."""
        user_idx = next(i for i, line in enumerate(dockerfile_instructions) if line.startswith("USER "))
        pip_idx = next(i for i, line in enumerate(dockerfile_instructions) if "pip install" in line)
        assert user_idx > pip_idx


class TestDockerfileEntrypoint:
    """Tests for the ENTRYPOINT configuration."""

    def test_dockerfile_entrypoint_is_skill_scan(self, dockerfile_instructions: list[str]) -> None:
        """ENTRYPOINT is skill-scan CLI."""
        ep_lines = [line for line in dockerfile_instructions if line.startswith("ENTRYPOINT ")]
        assert len(ep_lines) == 1
        assert ep_lines[0] == 'ENTRYPOINT ["skill-scan"]'


class TestDockerfileBuild:
    """Tests for the build configuration."""

    def test_dockerfile_copies_pyproject(self, dockerfile_instructions: list[str]) -> None:
        """Dockerfile copies pyproject.toml for installation."""
        copy_lines = [line for line in dockerfile_instructions if line.startswith("COPY ")]
        pyproject_copies = [line for line in copy_lines if "pyproject.toml" in line]
        assert len(pyproject_copies) == 1

    def test_dockerfile_copies_src(self, dockerfile_instructions: list[str]) -> None:
        """Dockerfile copies src/ directory."""
        copy_lines = [line for line in dockerfile_instructions if line.startswith("COPY ")]
        src_copies = [line for line in copy_lines if "src/" in line]
        assert len(src_copies) == 1

    def test_dockerfile_pip_install_no_cache(self, dockerfile_instructions: list[str]) -> None:
        """pip install uses --no-cache-dir for minimal image size."""
        pip_lines = [line for line in dockerfile_instructions if "pip install" in line]
        assert len(pip_lines) == 1
        assert "--no-cache-dir" in pip_lines[0]

    def test_dockerfile_workdir_is_scan(self, dockerfile_instructions: list[str]) -> None:
        """WORKDIR is /scan for volume mount point."""
        wd_lines = [line for line in dockerfile_instructions if line.startswith("WORKDIR ")]
        assert len(wd_lines) == 1
        assert wd_lines[0] == "WORKDIR /scan"

    def test_dockerfile_single_stage(self, dockerfile_lines: list[str]) -> None:
        """Dockerfile uses a single-stage build (one FROM)."""
        from_lines = [line for line in dockerfile_lines if line.startswith("FROM ")]
        assert len(from_lines) == 1

    def test_dockerfile_copies_readme(self, dockerfile_instructions: list[str]) -> None:
        """Dockerfile copies README.md (required by pyproject.toml)."""
        copy_lines = [line for line in dockerfile_instructions if line.startswith("COPY ")]
        readme_copies = [line for line in copy_lines if "README.md" in line]
        assert len(readme_copies) == 1


class TestDockerfileInstructionOrder:
    """Tests for correct instruction ordering in Dockerfile."""

    def test_dockerfile_instruction_order(self, dockerfile_instructions: list[str]) -> None:
        """Instructions start with FROM and end with USER, ENTRYPOINT."""
        first_words = [line.split()[0] for line in dockerfile_instructions]
        assert first_words[0] == "FROM"
        assert first_words[-1] == "ENTRYPOINT"
        assert first_words[-2] == "USER"


# --- .dockerignore tests ---


class TestDockerignoreExists:
    """Tests for .dockerignore file existence."""

    def test_dockerignore_exists(self) -> None:
        """.dockerignore exists at project root."""
        assert DOCKERIGNORE.is_file()


class TestDockerignoreExclusions:
    """Tests for required exclusion patterns."""

    @pytest.mark.parametrize(
        "pattern",
        [".git", ".github", ".agent", ".venv", "__pycache__", "tests/", "scripts/"],
        ids=[
            "git_dir",
            "github_dir",
            "agent_dir",
            "venv_dir",
            "pycache",
            "tests",
            "scripts",
        ],
    )
    def test_dockerignore_excludes_dev_dirs(self, dockerignore_entries: list[str], pattern: str) -> None:
        """.dockerignore excludes development directories."""
        assert pattern in dockerignore_entries

    @pytest.mark.parametrize(
        "pattern",
        ["*.pyc", "*.egg-info", "Makefile"],
        ids=["pyc_files", "egg_info", "makefile"],
    )
    def test_dockerignore_excludes_build_artifacts(
        self, dockerignore_entries: list[str], pattern: str
    ) -> None:
        """.dockerignore excludes build artifacts."""
        assert pattern in dockerignore_entries

    @pytest.mark.parametrize(
        "pattern",
        [".mypy_cache", ".pytest_cache", ".ruff_cache"],
        ids=["mypy_cache", "pytest_cache", "ruff_cache"],
    )
    def test_dockerignore_excludes_tool_caches(self, dockerignore_entries: list[str], pattern: str) -> None:
        """.dockerignore excludes tool caches."""
        assert pattern in dockerignore_entries


class TestDockerignoreInclusions:
    """Tests for files that must NOT be excluded."""

    def test_dockerignore_keeps_readme(self, dockerignore_entries: list[str]) -> None:
        """.dockerignore negates README.md exclusion."""
        assert "!README.md" in dockerignore_entries

    def test_dockerignore_does_not_exclude_src(self, dockerignore_entries: list[str]) -> None:
        """.dockerignore does not exclude src/ directory."""
        assert "src/" not in dockerignore_entries
        assert "src" not in dockerignore_entries

    def test_dockerignore_does_not_exclude_pyproject(self, dockerignore_entries: list[str]) -> None:
        """.dockerignore does not exclude pyproject.toml."""
        assert "pyproject.toml" not in dockerignore_entries
