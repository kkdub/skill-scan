"""Tests for AGENT-006 TOML stub and engine registration.

Verifies:
- R-IMP001: TOML stub entry with patterns=[]
- R005: Registered in _STRUCTURAL_DETECTORS in engine.py
"""

from __future__ import annotations

import inspect
import tomllib
from pathlib import Path
from typing import Any, cast


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TOML_PATH = _PROJECT_ROOT / "src" / "skill_scan" / "rules" / "data" / "agent_manipulation.toml"


def _load_agent006() -> dict[str, Any]:
    """Load the AGENT-006 rule from agent_manipulation.toml."""
    data = tomllib.loads(_TOML_PATH.read_text())
    rules = data.get("rules", {})
    result = rules.get("AGENT-006", {})
    return cast(dict[str, Any], result)


# ---------------------------------------------------------------------------
# 1. TOML stub tests
# ---------------------------------------------------------------------------
class TestAgent006Toml:
    """AGENT-006 must exist in agent_manipulation.toml with correct fields."""

    def test_agent006_exists_in_toml(self) -> None:
        rule = _load_agent006()
        assert rule, "AGENT-006 not found in agent_manipulation.toml"

    def test_severity_is_critical(self) -> None:
        rule = _load_agent006()
        assert rule["severity"] == "critical"

    def test_category_is_agent_manipulation(self) -> None:
        rule = _load_agent006()
        assert rule["category"] == "agent-manipulation"

    def test_patterns_is_empty_list(self) -> None:
        rule = _load_agent006()
        assert rule["patterns"] == [], f"Expected patterns=[], got {rule['patterns']!r}"

    def test_has_description(self) -> None:
        rule = _load_agent006()
        assert rule.get("description"), "description missing or empty"

    def test_has_recommendation(self) -> None:
        rule = _load_agent006()
        assert rule.get("recommendation"), "recommendation missing or empty"


# ---------------------------------------------------------------------------
# 2. Import test
# ---------------------------------------------------------------------------
class TestDetectCompoundAttackImport:
    """detect_compound_attack must be importable from the expected module."""

    def test_detect_compound_attack_is_callable(self) -> None:
        from skill_scan.rules._agent_compound_detector import detect_compound_attack

        assert callable(detect_compound_attack)


# ---------------------------------------------------------------------------
# 3. Engine registration test
# ---------------------------------------------------------------------------
class TestStructuralDetectorsRegistration:
    """detect_compound_attack must appear in _STRUCTURAL_DETECTORS."""

    def test_detect_compound_attack_in_structural_detectors(self) -> None:
        from skill_scan.rules.engine import _STRUCTURAL_DETECTORS

        names = [fn.__name__ for fn in _STRUCTURAL_DETECTORS]
        assert "detect_compound_attack" in names, (
            f"detect_compound_attack not in _STRUCTURAL_DETECTORS; found: {names}"
        )

    def test_suppress_agent_findings_precedes_detect_compound_attack(self) -> None:
        """suppress_agent_findings must run before detect_compound_attack."""
        from skill_scan.rules.engine import _STRUCTURAL_DETECTORS

        names = [fn.__name__ for fn in _STRUCTURAL_DETECTORS]
        idx_suppress = names.index("suppress_agent_findings")
        idx_compound = names.index("detect_compound_attack")
        assert idx_suppress < idx_compound, "suppress_agent_findings must precede detect_compound_attack"


# ---------------------------------------------------------------------------
# 4. Callback signature contract
# ---------------------------------------------------------------------------
class TestCallbackSignature:
    """detect_compound_attack must accept (lines, file_path, findings)."""

    def test_signature_has_three_parameters(self) -> None:
        from skill_scan.rules._agent_compound_detector import detect_compound_attack

        sig = inspect.signature(detect_compound_attack)
        params = list(sig.parameters.keys())
        assert len(params) == 3, f"Expected 3 params, got {len(params)}: {params}"

    def test_parameter_names_match_contract(self) -> None:
        from skill_scan.rules._agent_compound_detector import detect_compound_attack

        sig = inspect.signature(detect_compound_attack)
        params = list(sig.parameters.keys())
        assert params == ["lines", "file_path", "findings"], (
            f"Expected ['lines', 'file_path', 'findings'], got {params}"
        )


# ---------------------------------------------------------------------------
# 5. _AST_ONLY_RULES allowlist
# ---------------------------------------------------------------------------
class TestAstOnlyRulesAllowlist:
    """AGENT-006 must be in _AST_ONLY_RULES in test_rule_validation.py."""

    def test_agent006_in_ast_only_rules(self) -> None:
        validation_path = _PROJECT_ROOT / "tests" / "unit" / "test_rule_validation.py"
        content = validation_path.read_text()
        assert "AGENT-006" in content, "AGENT-006 not found in tests/unit/test_rule_validation.py"
