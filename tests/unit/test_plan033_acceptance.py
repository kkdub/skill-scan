"""Acceptance tests for PLAN-033: Module extraction and rename.

These exercise the full feature path across all parts of PLAN-033,
not just Part D's scope. They verify:
1. No *_helpers.py files remain in src/skill_scan/
2. All frozen modules have capacity headroom
3. All renamed modules exist on disk
4. All new extracted modules exist on disk
5. Deleted modules do not exist
"""

from __future__ import annotations

import pathlib
from typing import ClassVar

import pytest

# Project root: tests/unit/ -> tests/ -> project root
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SRC_DIR = _PROJECT_ROOT / "src" / "skill_scan"


class TestNoHelpersNamingDebt:
    """No *_helpers.py files remain in src/skill_scan/."""

    def test_zero_helpers_files(self) -> None:
        """src/skill_scan/ contains no *_helpers.py files."""
        matches = list(_SRC_DIR.glob("*_helpers.py"))
        assert len(matches) == 0, f"Found {len(matches)} *_helpers.py files: {[p.name for p in matches]}"


class TestFrozenModuleHeadroom:
    """All frozen modules are within their line-count ceilings."""

    _TARGETS: ClassVar[dict[str, int]] = {
        "_ast_split_resolve.py": 225,
        "_ast_rot13.py": 250,
        "rules/engine.py": 265,
        "_ast_imports.py": 160,
    }

    @pytest.mark.parametrize(
        ("filename", "max_lines"),
        list(_TARGETS.items()),
        ids=list(_TARGETS.keys()),
    )
    def test_module_within_ceiling(self, filename: str, max_lines: int) -> None:
        """Module has fewer lines than its capacity ceiling."""
        path = _SRC_DIR / filename
        assert path.exists(), f"{filename} not found"
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count <= max_lines, f"{filename} has {line_count} lines, exceeds ceiling of {max_lines}"


class TestRenamedModulesExist:
    """All renamed modules exist on disk."""

    _RENAMED: ClassVar[dict[str, str]] = {
        "_ast_imports.py": "_ast_helpers.py",
        "_ast_split_format.py": "_ast_split_helpers.py",
        "_ast_split_comprehension.py": "_ast_split_join_helpers.py",
        "_ast_split_star_unpack.py": "_ast_split_star_helpers.py",
        "_ast_split_map_resolver.py": "_ast_split_map_helpers.py",
        "_ast_split_int_list_tracker.py": "_ast_split_int_list_helpers.py",
        "_ast_symbol_table_assignments.py": "_ast_symbol_table_helpers.py",
        "_ast_symbol_table_dict_tracker.py": "_ast_symbol_table_dict_helpers.py",
        "_ast_symbol_table_self_attrs.py": "_ast_symbol_table_class_helpers.py",
        "_ast_symbol_table_returns.py": "_ast_symbol_table_return_helpers.py",
        "_decoder_base64_hex.py": "_decoder_helpers.py",
    }

    @pytest.mark.parametrize(
        ("new_name", "old_name"),
        list(_RENAMED.items()),
        ids=list(_RENAMED.keys()),
    )
    def test_new_module_exists(self, new_name: str, old_name: str) -> None:
        """New module file exists; old module file does not."""
        assert (_SRC_DIR / new_name).exists(), f"Renamed module {new_name} (was {old_name}) not found"
        assert not (_SRC_DIR / old_name).exists(), f"Old module {old_name} still exists alongside {new_name}"


class TestNewExtractedModulesExist:
    """All newly extracted modules exist on disk."""

    _NEW_MODULES: ClassVar[list[str]] = [
        "_ast_split_format_map.py",
        "_ast_rot13_branch_analysis.py",
        "_ast_string_resolver.py",
        "rules/_multiline_pi.py",
    ]

    @pytest.mark.parametrize("module", _NEW_MODULES)
    def test_extracted_module_exists(self, module: str) -> None:
        """Newly extracted module exists."""
        assert (_SRC_DIR / module).exists(), f"Extracted module {module} not found"


class TestDeletedModulesGone:
    """Deleted modules do not exist on disk."""

    def test_ast_join_helpers_deleted(self) -> None:
        """_ast_join_helpers.py was absorbed into _ast_string_resolver.py."""
        assert not (_SRC_DIR / "_ast_join_helpers.py").exists()
