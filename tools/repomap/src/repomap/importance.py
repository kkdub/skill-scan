"""
Important file detection for RepoMap.
"""

from collections.abc import Callable
from pathlib import PurePosixPath

IMPORTANT_FILENAMES = {
    "README.md",
    "README.txt",
    "readme.md",
    "README.rst",
    "README",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "package.json",
    "yarn.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".gitignore",
    ".gitattributes",
    ".dockerignore",
    "Makefile",
    "makefile",
    "CMakeLists.txt",
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "COPYING",
    "CHANGELOG.md",
    "CHANGELOG.txt",
    "HISTORY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    ".env",
    ".env.example",
    ".env.local",
    "tox.ini",
    "pytest.ini",
    ".pytest.ini",
    ".flake8",
    ".pylintrc",
    "mypy.ini",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
}

IMPORTANT_DIR_PATTERNS: dict[str, Callable[[str], bool]] = {
    ".github/workflows": lambda fname: fname.endswith((".yml", ".yaml")),
    ".github": lambda fname: fname.endswith((".md", ".yml", ".yaml")),
    "docs": lambda fname: fname.endswith((".md", ".rst", ".txt")),
}


def is_important(rel_file_path: str) -> bool:
    """Check if a file is considered important."""
    p = PurePosixPath(rel_file_path.replace("\\", "/"))
    file_name = p.name
    dir_name = str(p.parent)

    # Check specific directory patterns
    for important_dir, checker_func in IMPORTANT_DIR_PATTERNS.items():
        if dir_name == important_dir and checker_func(file_name):
            return True

    # Check if the full normalized path is important
    if str(p) in IMPORTANT_FILENAMES:
        return True

    # Check if just the basename is important
    if file_name in IMPORTANT_FILENAMES:
        return True

    return False


def filter_important_files(file_paths: list[str]) -> list[str]:
    """Filter list to only include important files."""
    return [path for path in file_paths if is_important(path)]
