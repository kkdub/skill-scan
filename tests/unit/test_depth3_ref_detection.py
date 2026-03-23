"""Tests for depth-3 getattr-on-ref and bare call resolution (PLAN-038 Part D).

Tests that:
- getattr(tracked_mod, 'system') stores func_ref AND emits EXEC-002 when dangerous
- getattr(tracked_mod, 'path') stores func_ref but does NOT emit EXEC-002
- Bare call on tracked func_ref (e('code')) emits EXEC-002 CRITICAL
- Full depth-3 chain emits both EXEC-006 (for __import__) and EXEC-002 (for resolved call)

Acceptance scenarios (plan-level, full feature path):
- Inline chain on __import__ return value detected
- Depth-2 assigned module ref resolved to dangerous call
- Depth-3 two-hop chain fully resolved
- No false positive on safe attribute access
"""

from __future__ import annotations

import ast

from skill_scan._ast_dynamic_exec_detector import detect_dynamic_exec
from skill_scan._ast_imports import build_alias_map
from skill_scan._ast_ref_tracker import RefEntry, build_ref_table
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding, Severity


def _findings_by_rule(code: str, rule_id: str) -> list[Finding]:
    """Return findings matching a specific rule_id from analyze_python."""
    return [f for f in analyze_python(code, "test.py") if f.rule_id == rule_id]


def _run_detector(code: str) -> tuple[list[Finding], dict[str, RefEntry]]:
    """Run detect_dynamic_exec and return findings + ref_table."""
    tree = ast.parse(code)
    alias_map = build_alias_map(tree)
    ref_table = build_ref_table(tree, alias_map)
    symbol_table = build_symbol_table(tree)
    findings = detect_dynamic_exec(
        tree,
        "test.py",
        alias_map,
        symbol_table,
        ref_table=ref_table,
    )
    return findings, ref_table


# ---------------------------------------------------------------------------
# PATH 1: getattr on tracked module ref -> store func_ref + maybe EXEC-002
# ---------------------------------------------------------------------------


class TestGetattrOnTrackedRef:
    """getattr(tracked_mod, 'attr') where tracked_mod is in ref_table."""

    def test_getattr_tracked_mod_system_emits_exec002(self) -> None:
        """getattr(os_mod, 'system') where os_mod is tracked -> EXEC-002."""
        code = "m = __import__('os')\nf = getattr(m, 'system')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1, f"Expected EXEC-002, got {findings}"

    def test_getattr_tracked_mod_eval_emits_exec002(self) -> None:
        """getattr(builtins_mod, 'eval') where builtins_mod is tracked -> EXEC-002."""
        code = "b = __import__('builtins')\nf = getattr(b, 'eval')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1, f"Expected EXEC-002, got {findings}"

    def test_getattr_tracked_mod_stores_func_ref(self) -> None:
        """getattr(os_mod, 'system') stores func_ref in ref_table."""
        code = "m = __import__('os')\nf = getattr(m, 'system')\n"
        findings, ref_table = _run_detector(code)
        assert "f" in ref_table, f"Expected 'f' in ref_table, got {list(ref_table.keys())}"
        entry = ref_table["f"]
        assert entry.kind == "func_ref"
        assert entry.resolved == "os.system"

    def test_getattr_tracked_mod_safe_attr_no_exec002(self) -> None:
        """getattr(os_mod, 'path') stores func_ref but no EXEC-002."""
        code = "m = __import__('os')\np = getattr(m, 'path')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) == 0, f"Unexpected EXEC-002 for os.path: {findings}"

    def test_getattr_tracked_mod_safe_attr_stores_ref(self) -> None:
        """getattr(os_mod, 'path') stores func_ref even though not dangerous."""
        code = "m = __import__('os')\np = getattr(m, 'path')\n"
        findings, ref_table = _run_detector(code)
        assert "p" in ref_table, f"Expected 'p' in ref_table, got {list(ref_table.keys())}"
        entry = ref_table["p"]
        assert entry.kind == "func_ref"
        assert entry.resolved == "os.path"

    def test_getattr_tracked_mod_popen_emits_exec002(self) -> None:
        """getattr(os_mod, 'popen') -> EXEC-002 (popen is dangerous)."""
        code = "m = __import__('os')\nf = getattr(m, 'popen')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1

    def test_getattr_on_untracked_name_no_exec002(self) -> None:
        """getattr(unknown_obj, 'system') should not emit EXEC-002 via ref path."""
        code = "f = getattr(some_obj, 'system')\n"
        # No EXEC-002 -- some_obj is not in ref_table
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PATH 2: Bare call on tracked func_ref -> EXEC-002
# ---------------------------------------------------------------------------


class TestBareCallOnFuncRef:
    """Call(func=Name) where Name resolves in ref_table as func_ref."""

    def test_bare_call_on_tracked_system_emits_exec002(self) -> None:
        """f = getattr(os_mod, 'system'); f('cmd') -> EXEC-002."""
        code = "m = __import__('os')\nf = getattr(m, 'system')\nf('whoami')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        # Should have EXEC-002 for f('whoami') bare call
        assert any(f.line == 3 for f in findings), (
            f"Expected EXEC-002 on line 3 (bare call), got lines {[f.line for f in findings]}"
        )

    def test_bare_call_on_tracked_eval_emits_exec002(self) -> None:
        """e = getattr(builtins_mod, 'eval'); e('code') -> EXEC-002."""
        code = "b = __import__('builtins')\ne = getattr(b, 'eval')\ne('1+1')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert any(f.line == 3 for f in findings), (
            f"Expected EXEC-002 on line 3, got lines {[f.line for f in findings]}"
        )

    def test_bare_call_severity_critical(self) -> None:
        """Bare call on dangerous func_ref should be CRITICAL severity."""
        code = "m = __import__('os')\nf = getattr(m, 'system')\nf('cmd')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        line3 = [f for f in findings if f.line == 3]
        assert len(line3) >= 1, "Expected EXEC-002 on line 3"
        assert any(f.severity == Severity.CRITICAL for f in line3)

    def test_bare_call_safe_func_ref_no_exec002(self) -> None:
        """p = getattr(json_mod, 'loads'); p('{}') -> no EXEC-002."""
        code = "m = __import__('json')\np = getattr(m, 'loads')\np('{}')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) == 0, f"Unexpected EXEC-002 for json.loads call: {findings}"


# ---------------------------------------------------------------------------
# Full depth-3 chain: __import__ + getattr + bare call
# ---------------------------------------------------------------------------


class TestFullDepth3Chain:
    """b = __import__('builtins'); e = getattr(b, 'eval'); e('code')."""

    def test_depth3_chain_emits_exec002(self) -> None:
        """Full chain produces EXEC-002 for the resolved call."""
        code = "b = __import__('builtins')\ne = getattr(b, 'eval')\ne('code')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1, f"Expected EXEC-002 from depth-3 chain, got {findings}"

    def test_depth3_chain_also_emits_exec006(self) -> None:
        """Full chain produces EXEC-006 for __import__ itself."""
        code = "b = __import__('builtins')\ne = getattr(b, 'eval')\ne('code')\n"
        all_findings = analyze_python(code, "test.py")
        rule_ids = {f.rule_id for f in all_findings}
        assert "EXEC-006" in rule_ids, "EXEC-006 must fire for __import__()"
        assert "EXEC-002" in rule_ids, "EXEC-002 must fire for depth-3 chain"

    def test_depth3_os_system_chain(self) -> None:
        """m = __import__('os'); f = getattr(m, 'system'); f('cmd')."""
        code = "m = __import__('os')\nf = getattr(m, 'system')\nf('whoami')\n"
        all_findings = analyze_python(code, "test.py")
        exec002 = [f for f in all_findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1, f"Expected EXEC-002, got {exec002}"

    def test_depth3_subprocess_call_chain(self) -> None:
        """mod = __import__('subprocess'); c = getattr(mod, 'call'); c(['ls'])."""
        code = "mod = __import__('subprocess')\nc = getattr(mod, 'call')\nc(['ls'])\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Scope-aware detection
# ---------------------------------------------------------------------------


class TestScopedDepth3:
    """Depth-3 detection works inside function and class scopes."""

    def test_function_scoped_depth3(self) -> None:
        """Depth-3 chain inside function body is detected."""
        code = "def exploit():\n    b = __import__('builtins')\n    e = getattr(b, 'eval')\n    e('code')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# ACCEPTANCE SCENARIOS (plan-level, full feature path)
# ---------------------------------------------------------------------------


class TestAcceptancePlanLevel:
    """Plan-level acceptance scenarios exercising the full feature path."""

    def test_inline_chain_on_import_return_detected(self) -> None:
        """Inline chain on __import__ return value detected as code execution."""
        findings = analyze_python("__import__('os').system('cmd')", "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1, (
            f"Expected EXEC-002 for inline chain, got rule_ids: {[f.rule_id for f in findings]}"
        )

    def test_depth2_assigned_module_ref_resolved(self) -> None:
        """Depth-2 assigned module ref resolved to dangerous call."""
        code = "m = __import__('os')\nm.system('cmd')\n"
        findings = analyze_python(code, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1
        assert any(f.severity == Severity.CRITICAL for f in exec002)

    def test_depth3_two_hop_chain_fully_resolved(self) -> None:
        """Depth-3 two-hop chain fully resolved."""
        code = "b = __import__('builtins')\ne = getattr(b, 'eval')\ne('code')\n"
        findings = analyze_python(code, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1, (
            f"Expected EXEC-002 for depth-3 chain, got rule_ids: {[f.rule_id for f in findings]}"
        )

    def test_no_false_positive_on_safe_attribute(self) -> None:
        """No false positive on safe attribute access."""
        code = "m = __import__('json')\nm.loads('{}')\n"
        findings = analyze_python(code, "test.py")
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) == 0, f"No EXEC-002 expected for json.loads, got {exec002}"
