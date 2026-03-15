"""
File I/O utilities for RepoMap.

Provides file reading and filesystem utilities with proper error handling.
"""

import os
from pathlib import Path


def default_read_text(filename: str, encoding: str = "utf-8", silent: bool = False) -> str | None:
    """Read text from file with error handling.

    Args:
        filename: Path to the file to read.
        encoding: Text encoding (default utf-8).
        silent: If True, suppress error messages.

    Returns:
        File contents as string, or None on error.
    """
    try:
        return Path(filename).read_text(encoding=encoding, errors="ignore")
    except FileNotFoundError:
        if not silent:
            print(f"Error: {filename} not found.")
        return None
    except IsADirectoryError:
        if not silent:
            print(f"Error: {filename} is a directory.")
        return None
    except OSError as e:
        if not silent:
            print(f"Error reading {filename}: {e}")
        return None
    except UnicodeError as e:
        if not silent:
            print(f"Error decoding {filename}: {e}")
        return None


def get_mtime(fname: str) -> float | None:
    """Get file modification time.

    Args:
        fname: Path to the file.

    Returns:
        Modification time as float, or None if file not found.
    """
    try:
        return os.path.getmtime(fname)
    except FileNotFoundError:
        return None
