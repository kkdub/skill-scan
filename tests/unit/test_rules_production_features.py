"""Tests for production rules using match_scope=file and exclude_mode=strict.

Validates that EXEC-009 (file-scope) and EXEC-010 (strict exclusion) rules
work correctly with positive, negative, and evasion test cases.
Also validates the public API boundary for match_content.
"""

from __future__ import annotations

import inspect

import pytest

from skill_scan.models import Rule
from skill_scan.rules import load_default_rules
from skill_scan.rules.engine import match_content


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Load full default rule set once for this module."""
    return load_default_rules()


class TestExec009FileScope:
    """EXEC-009: Multi-line base64 encoded execution (file-scope)."""

    # Positive: should detect
    def test_detects_exec_b64decode_multiline(self, rules: list[Rule]) -> None:
        content = "import base64\nexec(\n    base64.b64decode(\n        'payload'\n    )\n)"
        findings = match_content(content, "test.py", rules)
        assert any(f.rule_id == "EXEC-009" for f in findings)

    def test_detects_eval_b64decode_multiline(self, rules: list[Rule]) -> None:
        content = "import base64\neval(\n    base64.b64decode(\n        'payload'\n    )\n)"
        findings = match_content(content, "test.py", rules)
        assert any(f.rule_id == "EXEC-009" for f in findings)

    def test_detects_exec_compile_b64decode(self, rules: list[Rule]) -> None:
        content = (
            "exec(\n    compile(\n        base64.b64decode('code'),\n"
            "        '<string>',\n        'exec'\n    )\n)"
        )
        findings = match_content(content, "test.py", rules)
        assert any(f.rule_id == "EXEC-009" for f in findings)

    def test_detects_single_line_too(self, rules: list[Rule]) -> None:
        content = "exec(base64.b64decode('payload'))"
        findings = match_content(content, "test.py", rules)
        assert any(f.rule_id == "EXEC-009" for f in findings)

    # Negative: should NOT detect
    def test_no_match_plain_exec(self, rules: list[Rule]) -> None:
        content = "exec('print(1)')"
        findings = match_content(content, "test.py", rules)
        assert not any(f.rule_id == "EXEC-009" for f in findings)

    def test_no_match_base64_decode_without_exec(self, rules: list[Rule]) -> None:
        content = "data = base64.b64decode('some_data')"
        findings = match_content(content, "test.py", rules)
        assert not any(f.rule_id == "EXEC-009" for f in findings)

    def test_excluded_test_fixture(self, rules: list[Rule]) -> None:
        """Exclude pattern checked on the line where the match starts."""
        content = "# test fixture: exec(base64.b64decode('payload'))"
        findings = match_content(content, "test.py", rules)
        assert not any(f.rule_id == "EXEC-009" for f in findings)


class TestExec010StrictExclusion:
    """EXEC-010: eval/exec with user input, strict exclusion mode."""

    # Positive: should detect
    def test_detects_eval_user_input(self, rules: list[Rule]) -> None:
        content = "result = eval(user_input)"
        findings = match_content(content, "test.py", rules)
        assert any(f.rule_id == "EXEC-010" for f in findings)

    def test_detects_exec_user_data(self, rules: list[Rule]) -> None:
        content = "exec(user_data)"
        findings = match_content(content, "test.py", rules)
        assert any(f.rule_id == "EXEC-010" for f in findings)

    def test_detects_eval_input_call(self, rules: list[Rule]) -> None:
        content = "eval(input('Enter code: '))"
        findings = match_content(content, "test.py", rules)
        assert any(f.rule_id == "EXEC-010" for f in findings)

    # Evasion: strict mode blocks piggyback suppression
    def test_piggyback_comment_not_suppressive(self, rules: list[Rule]) -> None:
        """Comment mentioning safe_eval should NOT suppress the real eval()."""
        content = "eval(user_input) # use safe_eval instead"
        findings = match_content(content, "test.py", rules)
        assert any(f.rule_id == "EXEC-010" for f in findings)

    # Negative: legitimate exclusion still works
    def test_safe_eval_suppresses(self, rules: list[Rule]) -> None:
        """ast.literal_eval overlaps match region and should suppress."""
        content = "result = ast.literal_eval(user_input)"
        findings = match_content(content, "test.py", rules)
        assert not any(f.rule_id == "EXEC-010" for f in findings)

    def test_no_match_without_user_or_input(self, rules: list[Rule]) -> None:
        content = "eval('2 + 2')"
        findings = match_content(content, "test.py", rules)
        assert not any(f.rule_id == "EXEC-010" for f in findings)

    def test_no_match_exec_without_user_or_input(self, rules: list[Rule]) -> None:
        content = "exec(compiled_code)"
        findings = match_content(content, "test.py", rules)
        assert not any(f.rule_id == "EXEC-010" for f in findings)


class TestMatchContentPublicAPI:
    """Verify match_content public signature hides _depth."""

    def test_no_depth_in_public_signature(self) -> None:
        """Public match_content() must not expose _depth parameter."""
        sig = inspect.signature(match_content)
        param_names = list(sig.parameters.keys())
        assert "_depth" not in param_names
        assert param_names == ["content", "file_path", "rules"]

    def test_match_content_rejects_depth_kwarg(self) -> None:
        """Calling match_content with _depth keyword should raise TypeError."""
        with pytest.raises(TypeError):
            match_content("", "test.py", [], _depth=1)  # type: ignore[call-arg]
