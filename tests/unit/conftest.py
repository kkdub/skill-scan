"""Shared fixtures and helpers for tests/unit/."""

from __future__ import annotations

import pytest

from skill_scan.models import Rule
from skill_scan.rules import load_default_rules


@pytest.fixture(scope="module")
def pi_rules() -> list[Rule]:
    """Load all prompt injection rules once for the test module."""
    all_rules = load_default_rules()
    return [r for r in all_rules if r.rule_id.startswith("PI-")]
