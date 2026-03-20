"""Tests for scripts/rename_module.py — the bulk module rename tool.

Tests cover:
- Import rewriting logic (skill_scan.* and tests.unit.* imports)
- Test file rename mapping
- Idempotency (skip already-renamed)
- Full rename mapping completeness
"""

from __future__ import annotations

from typing import ClassVar

from scripts.rename_module import RENAME_MAP, rewrite_imports, map_test_file


# ===================================================================
# Import rewriting — skill_scan.* imports
# ===================================================================


class TestRewriteSkillScanImports:
    """Rewriting 'from skill_scan.{old} import ...' lines."""

    def test_from_import(self) -> None:
        line = "from skill_scan._ast_helpers import build_alias_map\n"
        result = rewrite_imports(line, {"_ast_helpers": "_ast_imports"})
        assert result == "from skill_scan._ast_imports import build_alias_map\n"

    def test_import_module(self) -> None:
        line = "import skill_scan._ast_helpers\n"
        result = rewrite_imports(line, {"_ast_helpers": "_ast_imports"})
        assert result == "import skill_scan._ast_imports\n"

    def test_from_import_as_reexport(self) -> None:
        """The 'import X as X' re-export pattern must be rewritten."""
        line = "from skill_scan._ast_helpers import build_alias_map as build_alias_map\n"
        result = rewrite_imports(line, {"_ast_helpers": "_ast_imports"})
        assert result == "from skill_scan._ast_imports import build_alias_map as build_alias_map\n"

    def test_multiple_renames_in_one_file(self) -> None:
        content = (
            "from skill_scan._ast_helpers import build_alias_map\n"
            "from skill_scan._decoder_helpers import decode_base64\n"
            "# comment\n"
            "x = 1\n"
        )
        rename_map = {
            "_ast_helpers": "_ast_imports",
            "_decoder_helpers": "_decoder_base64_hex",
        }
        result = rewrite_imports(content, rename_map)
        assert "from skill_scan._ast_imports import build_alias_map\n" in result
        assert "from skill_scan._decoder_base64_hex import decode_base64\n" in result
        assert "# comment\n" in result

    def test_no_match_unchanged(self) -> None:
        line = "from skill_scan.models import Finding\n"
        result = rewrite_imports(line, {"_ast_helpers": "_ast_imports"})
        assert result == line

    def test_multiline_imports_from(self) -> None:
        """Multi-line from-import with parens."""
        content = "from skill_scan._ast_helpers import (\n    build_alias_map,\n    get_call_name,\n)\n"
        result = rewrite_imports(content, {"_ast_helpers": "_ast_imports"})
        assert "from skill_scan._ast_imports import (\n" in result


# ===================================================================
# Import rewriting — tests.unit.* imports (inter-test)
# ===================================================================


class TestRewriteInterTestImports:
    """Rewriting 'from tests.unit.{old} import ...' lines."""

    def test_kwargs_test_helpers_rename(self) -> None:
        line = "from tests.unit.kwargs_test_helpers import detect as _detect\n"
        result = rewrite_imports(line, {"kwargs_test_helpers": "kwargs_test_utils"})
        assert result == "from tests.unit.kwargs_test_utils import detect as _detect\n"

    def test_test_module_cross_import(self) -> None:
        """test_ast_split_helpers_percent imports from test_ast_split_helpers."""
        line = "from tests.unit.test_ast_split_helpers import _detect\n"
        result = rewrite_imports(line, {"test_ast_split_helpers": "test_ast_split_format"})
        assert result == "from tests.unit.test_ast_split_format import _detect\n"

    def test_inter_test_with_multiple_imports(self) -> None:
        line = "from tests.unit.kwargs_test_helpers import _FILE, detect as _detect, detect_full as _detect_full\n"
        result = rewrite_imports(line, {"kwargs_test_helpers": "kwargs_test_utils"})
        assert (
            "from tests.unit.kwargs_test_utils import _FILE, detect as _detect, detect_full as _detect_full\n"
            == result
        )


# ===================================================================
# String literals and comments must NOT be rewritten
# ===================================================================


class TestNoRewriteStringsOrComments:
    """Import rewriting must only affect import statements."""

    def test_string_literal_unchanged(self) -> None:
        line = '    "_ast_helpers.py",\n'
        result = rewrite_imports(line, {"_ast_helpers": "_ast_imports"})
        assert result == line

    def test_comment_unchanged(self) -> None:
        line = "# This references _ast_helpers for context\n"
        result = rewrite_imports(line, {"_ast_helpers": "_ast_imports"})
        assert result == line

    def test_docstring_unchanged(self) -> None:
        content = '"""See _ast_helpers for details."""\n'
        result = rewrite_imports(content, {"_ast_helpers": "_ast_imports"})
        assert result == content

    def test_assignment_unchanged(self) -> None:
        line = "module = '_ast_helpers'\n"
        result = rewrite_imports(line, {"_ast_helpers": "_ast_imports"})
        assert result == line


# ===================================================================
# Test file rename mapping
# ===================================================================


class TestTestFileMapping:
    """map_test_file maps source module rename to test file rename."""

    def test_basic_mapping(self) -> None:
        result = map_test_file("_ast_helpers", "_ast_imports")
        assert result == ("test_ast_helpers.py", "test_ast_imports.py")

    def test_strips_leading_underscore(self) -> None:
        """Module _ast_split_helpers -> test file test_ast_split_helpers.py."""
        result = map_test_file("_ast_split_helpers", "_ast_split_format")
        assert result == ("test_ast_split_helpers.py", "test_ast_split_format.py")

    def test_decoder_helpers(self) -> None:
        result = map_test_file("_decoder_helpers", "_decoder_base64_hex")
        assert result == ("test_decoder_helpers.py", "test_decoder_base64_hex.py")

    def test_no_leading_underscore_module(self) -> None:
        """If module has no leading underscore, mapping still works."""
        result = map_test_file("decoder_helpers", "decoder_base64_hex")
        assert result == ("test_decoder_helpers.py", "test_decoder_base64_hex.py")


# ===================================================================
# Full rename mapping completeness
# ===================================================================


class TestRenameMapCompleteness:
    """Validate the RENAME_MAP covers all expected modules."""

    EXPECTED_RENAMES: ClassVar[dict[str, str]] = {
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

    def test_all_expected_modules_present(self) -> None:
        for old, new in self.EXPECTED_RENAMES.items():
            assert old in RENAME_MAP, f"Missing rename for {old}"
            assert RENAME_MAP[old] == new, f"Wrong rename for {old}: got {RENAME_MAP[old]}, expected {new}"

    def test_no_unexpected_source_renames(self) -> None:
        """RENAME_MAP should only contain known source module renames."""
        # Source renames (skill_scan.*) — filter out test-only renames
        source_renames = {
            k: v for k, v in RENAME_MAP.items() if not k.startswith("test_") and k != "kwargs_test_helpers"
        }
        for old in source_renames:
            assert old in self.EXPECTED_RENAMES, f"Unexpected rename: {old}"

    def test_inter_test_renames_present(self) -> None:
        """kwargs_test_helpers and cross-test imports must be in the map."""
        assert "kwargs_test_helpers" in RENAME_MAP
        assert RENAME_MAP["kwargs_test_helpers"] == "kwargs_test_utils"

    def test_test_file_cross_import_rename(self) -> None:
        """test_ast_split_helpers is imported by test_ast_split_helpers_percent."""
        assert "test_ast_split_helpers" in RENAME_MAP
        assert RENAME_MAP["test_ast_split_helpers"] == "test_ast_split_format"


# ===================================================================
# Idempotency
# ===================================================================


class TestIdempotency:
    """Already-rewritten content should not be double-rewritten."""

    def test_already_renamed_import_unchanged(self) -> None:
        """If import already uses new name, it should not be modified."""
        line = "from skill_scan._ast_imports import build_alias_map\n"
        result = rewrite_imports(line, {"_ast_helpers": "_ast_imports"})
        assert result == line

    def test_rewrite_is_idempotent(self) -> None:
        """Applying rewrite twice produces the same result."""
        original = "from skill_scan._ast_helpers import X\n"
        rename_map = {"_ast_helpers": "_ast_imports"}
        first = rewrite_imports(original, rename_map)
        second = rewrite_imports(first, rename_map)
        assert first == second
