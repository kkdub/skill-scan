#!/usr/bin/env python3
"""Git operations for architecture smell detection."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class GitError(Exception):
    """Raised when git operations fail."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _run_git_command(args: list[str], repo_root: Path) -> str:
    """Run a git command and return stdout.

    Args:
        args: Git command arguments (without 'git' prefix)
        repo_root: Repository root path

    Returns:
        The command's stdout output

    Raises:
        GitError: If git is not installed, not a repo, or command fails
    """
    cmd = ["git", "-C", str(repo_root), *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except FileNotFoundError:
        raise GitError("git is not installed or not in PATH") from None
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        raise GitError(f"git command failed: {stderr}") from None
    except OSError as e:
        raise GitError(f"Failed to run git: {e}") from None


def git_tracked_files(repo_root: Path) -> list[Path]:
    """Get all tracked Python files.

    Raises:
        GitError: If git operations fail
    """
    output = _run_git_command(["ls-files", "-z", "*.py"], repo_root)
    return [repo_root / f for f in output.split("\0") if f]


def git_diff_files(repo_root: Path) -> list[Path]:
    """Get Python files changed in current diff (staged + unstaged).

    Raises:
        GitError: If git operations fail
    """
    # Get staged changes
    staged_cmd = ["diff", "--cached", "--name-only", "-z", "--", "*.py"]
    staged_output = _run_git_command(staged_cmd, repo_root)
    # Get unstaged changes
    unstaged_output = _run_git_command(["diff", "--name-only", "-z", "--", "*.py"], repo_root)
    files: set[str] = set()
    for output in (staged_output, unstaged_output):
        files.update(f for f in output.split("\0") if f)
    return [repo_root / f for f in files if (repo_root / f).exists()]
