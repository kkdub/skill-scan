"""Tests for Part D: Documentation and status updates (PLAN-040).

Validates that ARCHITECTURE-REFERENCE.md, improvements.yaml, and debt.yaml
have been correctly updated per PLAN-040 Part D criteria.
"""

from __future__ import annotations

import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ARCH_REF = ROOT / ".agent" / "ARCHITECTURE-REFERENCE.md"
IMPROVEMENTS = ROOT / ".agent" / "status" / "improvements.yaml"


class TestArchitectureReferenceInlineChainDetector:
    """ARCHITECTURE-REFERENCE.md lists _ast_inline_chain_detector.py with exports and role."""

    @pytest.fixture(autouse=True)
    def _load(self) -> None:  # noqa: dead code
        self.content = ARCH_REF.read_text()

    def test_module_listed(self) -> None:
        """The new module _ast_inline_chain_detector.py is documented."""
        assert "_ast_inline_chain_detector.py" in self.content

    def test_detect_inline_import_chain_export(self) -> None:
        """The _detect_inline_import_chain function is documented as an export."""
        assert "_detect_inline_import_chain" in self.content

    def test_inline_chain_attrs_export(self) -> None:
        """The _INLINE_CHAIN_ATTRS constant is documented as an export."""
        assert "_INLINE_CHAIN_ATTRS" in self.content

    def test_import_call_names_export(self) -> None:
        """The _IMPORT_CALL_NAMES constant is documented as an export."""
        assert "_IMPORT_CALL_NAMES" in self.content

    def test_role_description(self) -> None:
        """The module's role as inline import chain detector is described."""
        content_lower = self.content.lower()
        assert "inline" in content_lower and "chain" in content_lower


class TestArchitectureReferenceMethodScope:
    """ARCHITECTURE-REFERENCE.md documents method-scoped ref_table behavior."""

    @pytest.fixture(autouse=True)
    def _load(self) -> None:  # noqa: dead code
        self.content = ARCH_REF.read_text()

    def test_method_scope_true_documented(self) -> None:
        """method_scope=True is documented for build_ref_table and detect_dynamic_exec."""
        assert "method_scope=True" in self.content

    def test_scope_key_format_documented(self) -> None:
        """The scope key format ClassName.method.var is documented."""
        assert "ClassName.method.var" in self.content

    def test_build_ref_table_mentioned(self) -> None:
        """build_ref_table is mentioned in the method-scope documentation."""
        assert "build_ref_table" in self.content

    def test_detect_dynamic_exec_mentioned(self) -> None:
        """detect_dynamic_exec is mentioned in the method-scope documentation."""
        assert "detect_dynamic_exec" in self.content


class TestImprovementsYamlPlan038Resolved:
    """improvements.yaml PLAN-038 entries are removed with Resolved-by PLAN-040 comments."""

    @pytest.fixture(autouse=True)
    def _load(self) -> None:  # noqa: dead code
        self.content = IMPROVEMENTS.read_text()

    def test_no_plan038_entries_remain(self) -> None:
        """No active PLAN-038-tagged entries remain in the improvements list."""
        lines = self.content.splitlines()
        plan_tags: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("plan:"):
                plan_tags.append(stripped.split(":", 1)[1].strip())
        assert "PLAN-038" not in plan_tags, "PLAN-038 entry still active in improvements.yaml"

    def test_resolved_by_plan040_comment(self) -> None:
        """A Resolved-by: PLAN-040 comment exists in the file."""
        assert "PLAN-040" in self.content

    def test_inline_chain_attrs_entry_removed(self) -> None:
        """The _INLINE_CHAIN_ATTRS improvement entry is no longer an active entry."""
        active = [
            line
            for line in self.content.splitlines()
            if line.strip().startswith("- description:") and "_INLINE_CHAIN_ATTRS" in line
        ]
        assert not active, "PLAN-038 _INLINE_CHAIN_ATTRS entry still active"

    def test_method_scope_entry_removed(self) -> None:
        """The method_scope improvement entry is no longer an active entry."""
        active = [
            line
            for line in self.content.splitlines()
            if line.strip().startswith("- description:") and "method_scope" in line
        ]
        assert not active, "PLAN-038 method_scope entry still active"

    def test_rebinding_entry_removed(self) -> None:
        """The rebinding improvement entry is no longer an active entry."""
        active = [
            line
            for line in self.content.splitlines()
            if line.strip().startswith("- description:") and "rebind" in line
        ]
        assert not active, "PLAN-038 rebinding entry still active"
