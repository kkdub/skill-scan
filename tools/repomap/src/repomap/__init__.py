"""
RepoMap -- portable Python package for generating agent-friendly codebase structure maps.

Public API:
    RepoMap       - Main orchestration class
    Tag           - Namedtuple for parsed code symbols
    FileReport    - Dataclass describing processing results
    get_scm_fname - Look up tree-sitter .scm query file for a language
    is_important  - Check whether a file is considered "important"
"""

from repomap.core import RepoMap
from repomap.importance import is_important
from repomap.languages import get_scm_fname
from repomap.models import FileReport
from repomap.tags import Tag

__all__ = [
    "FileReport",
    "RepoMap",
    "Tag",
    "get_scm_fname",
    "is_important",
]
