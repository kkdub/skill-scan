"""
Data models for RepoMap.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass(slots=True)
class FileReport:
    """Report about files processed during map generation."""

    excluded: Dict[str, str]
    definition_matches: int
    reference_matches: int
    total_files_considered: int
