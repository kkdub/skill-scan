"""
Disk cache management for RepoMap.
"""

import shutil
import sqlite3
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

from repomap.tags import Tag

# Constants
CACHE_VERSION = 1
SQLITE_ERRORS = (sqlite3.OperationalError, sqlite3.DatabaseError)

# Type alias for the cache backend (diskcache.Cache or plain dict)
CacheBackend = Any


def make_cache_dir_name(version: int = CACHE_VERSION) -> str:
    """Return the cache directory name for the given version."""
    return f".repomap.tags.cache.v{version}"


def load_cache(
    cache_dir: Path,
    on_warning: Callable[[str], None] = lambda msg: None,
) -> CacheBackend:
    """Load or create the persistent tags cache.

    Args:
        cache_dir: Directory where the cache files are stored.
        on_warning: Callable for warning messages.

    Returns:
        A diskcache.Cache instance, or a plain dict as fallback.
    """
    try:
        import diskcache

        return diskcache.Cache(str(cache_dir))
    except Exception as e:
        on_warning(f"Failed to load tags cache: {e}")
        return {}


def close_cache(cache: CacheBackend) -> None:
    """Close the cache backend if it supports closing.

    Args:
        cache: The cache backend (diskcache.Cache or dict).
    """
    if hasattr(cache, "close"):
        cache.close()


def reset_cache(
    cache_dir: Path,
    on_warning: Callable[[str], None] = lambda msg: None,
) -> CacheBackend:
    """Delete and recreate the tags cache.

    Args:
        cache_dir: Directory where the cache files are stored.
        on_warning: Callable for warning messages.

    Returns:
        A fresh cache backend.
    """
    try:
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        return load_cache(cache_dir, on_warning)
    except Exception as e:
        on_warning(f"Failed to recreate tags cache, using in-memory cache: {e}")
        return {}


def get_cached_tags(
    cache: CacheBackend,
    fname: str,
    file_mtime: float,
) -> list[Tag] | None:
    """Retrieve cached tags if the file has not been modified.

    Args:
        cache: The cache backend (diskcache.Cache or dict).
        fname: Absolute file path used as cache key.
        file_mtime: Current modification time of the file.

    Returns:
        Cached list of Tags, or None on cache miss.
    """
    with suppress(*SQLITE_ERRORS):
        cached_entry = cache.get(fname)
        if cached_entry and cached_entry.get("mtime") == file_mtime:
            tags: list[Tag] = cached_entry["data"]
            return tags
    return None


def set_cached_tags(
    cache: CacheBackend,
    fname: str,
    file_mtime: float,
    tags: list[Tag],
) -> None:
    """Store tags in the cache.

    Args:
        cache: The cache backend (diskcache.Cache or dict).
        fname: Absolute file path used as cache key.
        file_mtime: Current modification time of the file.
        tags: List of Tag namedtuples to cache.
    """
    with suppress(*SQLITE_ERRORS):
        cache[fname] = {"mtime": file_mtime, "data": tags}
