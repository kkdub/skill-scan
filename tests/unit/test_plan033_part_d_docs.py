"""Tests for PLAN-033 Part D: Documentation updates.

Validates that all documentation files (CLAUDE.md, README.md,
ARCHITECTURE-REFERENCE.md, CODE-PATTERNS.md, debt.yaml) reference
new module names and contain no stale *_helpers.py references.
"""

from __future__ import annotations

import pathlib
import re

import pytest

# Project root: tests/unit/ -> tests/ -> project root
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SRC_DIR = _PROJECT_ROOT / "src" / "skill_scan"


# --- Rename mapping ---
_OLD_TO_NEW = {
    "_ast_helpers": "_ast_imports",
    "_ast_split_helpers": "_ast_split_format",
    "_ast_split_join_helpers": "_ast_split_comprehension",
    "_ast_split_star_helpers": "_ast_split_star_unpack",
    "_ast_split_map_helpers": "_ast_split_map_resolver",
    "_ast_split_int_list_helpers": "_ast_split_int_list_tracker",
    "_ast_symbol_table_helpers": "_ast_symbol_table_assignments",
    "_ast_symbol_table_dict_helpers": "_ast_symbol_table_dict_tracker",
    "_ast_symbol_table_class_helpers": "_ast_symbol_table_self_attrs",
    "_ast_symbol_table_return_helpers": "_ast_symbol_table_returns",
    "_decoder_helpers": "_decoder_base64_hex",
}

_NEW_MODULES = [
    "_ast_split_format_map.py",
    "_ast_rot13_branch_analysis.py",
    "_ast_string_resolver.py",
    "rules/_multiline_pi.py",
]

_DELETED_MODULES = [
    "_ast_join_helpers.py",
]

# Files to check for stale references
_DOC_FILES = {
    "CLAUDE.md": _PROJECT_ROOT / "CLAUDE.md",
    "ARCHITECTURE-REFERENCE.md": (_PROJECT_ROOT / ".agent" / "ARCHITECTURE-REFERENCE.md"),
    "CODE-PATTERNS.md": _PROJECT_ROOT / ".agent" / "standards" / "CODE-PATTERNS.md",
}


class TestClaudeMdProjectStructure:
    """CLAUDE.md Project Structure section lists all new filenames."""

    def test_new_module_names_present(self) -> None:
        """Every renamed module's new name appears in CLAUDE.md."""
        content = (_PROJECT_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        for new_name in _OLD_TO_NEW.values():
            assert new_name in content, f"New module name '{new_name}' not found in CLAUDE.md"

    def test_new_extracted_modules_present(self) -> None:
        """Every newly created module appears in CLAUDE.md."""
        content = (_PROJECT_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        for module in _NEW_MODULES:
            # Strip path prefix for matching (e.g., rules/_multiline_pi.py)
            basename = pathlib.Path(module).name
            assert basename in content, f"New module '{module}' not found in CLAUDE.md"

    def test_deleted_module_not_referenced(self) -> None:
        """Deleted _ast_join_helpers.py is not referenced in CLAUDE.md."""
        content = (_PROJECT_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        for module in _DELETED_MODULES:
            assert module not in content, f"Deleted module '{module}' still referenced in CLAUDE.md"


class TestNoStaleHelperReferences:
    """No documentation file references old *_helpers.py names."""

    @pytest.mark.parametrize("old_name", list(_OLD_TO_NEW.keys()))
    def test_claude_md_no_old_name(self, old_name: str) -> None:
        """CLAUDE.md contains no reference to old module name."""
        content = (_PROJECT_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        # Match the old name as a module reference (with .py or as bare name)
        # but not as part of a larger word (e.g., "symbol_table_helpers" but
        # not "symbol_table_helpers_extra")
        pattern = rf"\b{re.escape(old_name)}(\.py)?\b"
        matches = re.findall(pattern, content)
        assert len(matches) == 0, f"Old module name '{old_name}' still appears in CLAUDE.md"

    @pytest.mark.parametrize("old_name", list(_OLD_TO_NEW.keys()))
    def test_architecture_ref_no_old_name(self, old_name: str) -> None:
        """ARCHITECTURE-REFERENCE.md contains no old module name."""
        path = _DOC_FILES["ARCHITECTURE-REFERENCE.md"]
        if not path.exists():
            pytest.skip("ARCHITECTURE-REFERENCE.md not found")
        content = path.read_text(encoding="utf-8")
        pattern = rf"\b{re.escape(old_name)}(\.py)?\b"
        matches = re.findall(pattern, content)
        assert len(matches) == 0, f"Old name '{old_name}' still in ARCHITECTURE-REFERENCE.md"

    @pytest.mark.parametrize("old_name", list(_OLD_TO_NEW.keys()))
    def test_code_patterns_no_old_name(self, old_name: str) -> None:
        """CODE-PATTERNS.md contains no old module name."""
        path = _DOC_FILES["CODE-PATTERNS.md"]
        if not path.exists():
            pytest.skip("CODE-PATTERNS.md not found")
        content = path.read_text(encoding="utf-8")
        pattern = rf"\b{re.escape(old_name)}(\.py)?\b"
        matches = re.findall(pattern, content)
        assert len(matches) == 0, f"Old name '{old_name}' still in CODE-PATTERNS.md"


class TestReadmeMdModuleStructure:
    """README.md describes current module structure."""

    def test_readme_exists(self) -> None:
        """README.md exists at project root."""
        assert (_PROJECT_ROOT / "README.md").exists()

    def test_readme_no_deleted_modules(self) -> None:
        """README.md does not reference deleted modules."""
        content = (_PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        for module in _DELETED_MODULES:
            assert module not in content, f"Deleted module '{module}' still in README.md"

    def test_readme_no_old_helper_names(self) -> None:
        """README.md does not reference old *_helpers.py names."""
        content = (_PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        for old_name in _OLD_TO_NEW:
            pattern = rf"\b{re.escape(old_name)}(\.py)?\b"
            matches = re.findall(pattern, content)
            assert len(matches) == 0, f"Old name '{old_name}' still in README.md"


class TestDebtYaml:
    """debt.yaml file paths updated to new module names."""

    _DEBT_PATH = _PROJECT_ROOT / ".agent" / "status" / "debt.yaml"

    def test_debt_yaml_exists(self) -> None:
        """debt.yaml exists."""
        assert self._DEBT_PATH.exists()

    def test_debt029_not_present(self) -> None:
        """DEBT-029 is not present in debt.yaml (resolved in Part A)."""
        content = self._DEBT_PATH.read_text(encoding="utf-8")
        assert "DEBT-029" not in content, "DEBT-029 should be removed"

    def test_no_old_helper_file_paths(self) -> None:
        """debt.yaml contains no references to old *_helpers.py filenames."""
        content = self._DEBT_PATH.read_text(encoding="utf-8")
        for old_name in _OLD_TO_NEW:
            pattern = rf"\b{re.escape(old_name)}(\.py)?\b"
            matches = re.findall(pattern, content)
            assert len(matches) == 0, f"Old name '{old_name}' still in debt.yaml"
