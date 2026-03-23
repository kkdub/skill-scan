"""Tests for depth-2 attribute access on tracked module refs (PLAN-038 Part C).

Tests that detect_dynamic_exec emits EXEC-002 CRITICAL when a Call uses an
attribute on a tracked module ref from ref_table, and that func_ref
assignments are tracked for downstream use (Part D).
"""

from __future__ import annotations

import ast

from skill_scan._ast_dynamic_exec_detector import detect_dynamic_exec
from skill_scan._ast_imports import build_alias_map
from skill_scan._ast_ref_tracker import build_ref_table
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding, Severity


def _findings_by_rule(code: str, rule_id: str) -> list[Finding]:
    """Return findings matching a specific rule_id from analyze_python."""
    return [f for f in analyze_python(code, "test.py") if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# PATH 1: Attribute access on tracked module ref -> EXEC-002
# ---------------------------------------------------------------------------


class TestDepth2ModuleAttrDetection:
    """m = __import__('os'); m.system('cmd') should emit EXEC-002 CRITICAL."""

    def test_import_os_system_emits_exec002(self) -> None:
        """__import__('os') assigned to m, m.system() call -> EXEC-002."""
        code = "m = __import__('os')\nm.system('whoami')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1, f"Expected EXEC-002, got {findings}"
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_import_os_popen_emits_exec002(self) -> None:
        """__import__('os') assigned to m, m.popen() -> EXEC-002."""
        code = "m = __import__('os')\nm.popen('id')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_importlib_subprocess_call_emits_exec002(self) -> None:
        """importlib.import_module('subprocess') then mod.call() -> EXEC-002."""
        code = "import importlib\nmod = importlib.import_module('subprocess')\nmod.call(['ls'])\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1, f"Expected EXEC-002, got {findings}"
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_import_builtins_eval_emits_exec002(self) -> None:
        """__import__('builtins') then b.eval('code') -> EXEC-002."""
        code = "b = __import__('builtins')\nb.eval('1+1')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_import_os_exec_emits_exec002(self) -> None:
        """__import__('os') then m.exec() -> EXEC-002 (exec is in _DANGEROUS_NAMES)."""
        code = "m = __import__('os')\nm.exec('code')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1

    def test_matched_text_shows_resolved_chain(self) -> None:
        """EXEC-002 finding matched_text references the resolved module.attr."""
        code = "m = __import__('os')\nm.system('whoami')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1
        # The finding should reference the resolved module chain
        matched = [f for f in findings if "os" in (f.matched_text or "")]
        assert len(matched) >= 1, "matched_text should reference resolved module"


# ---------------------------------------------------------------------------
# EXEC-006 still fires alongside EXEC-002 (no regression)
# ---------------------------------------------------------------------------


class TestExec006StillFires:
    """__import__() itself must still produce EXEC-006 alongside EXEC-002."""

    def test_exec006_and_exec002_both_present(self) -> None:
        """m = __import__('os'); m.system() should emit both rule IDs."""
        code = "m = __import__('os')\nm.system('whoami')\n"
        all_findings = analyze_python(code, "test.py")
        rule_ids = {f.rule_id for f in all_findings}
        assert "EXEC-006" in rule_ids, "EXEC-006 must still fire for __import__()"
        assert "EXEC-002" in rule_ids, "EXEC-002 must fire for m.system()"

    def test_importlib_exec006_still_fires(self) -> None:
        """importlib.import_module() should still produce EXEC-006."""
        code = "import importlib\nmod = importlib.import_module('subprocess')\nmod.call(['ls'])\n"
        all_findings = analyze_python(code, "test.py")
        rule_ids = {f.rule_id for f in all_findings}
        assert "EXEC-006" in rule_ids, "EXEC-006 must still fire for importlib.import_module()"
        assert "EXEC-002" in rule_ids


# ---------------------------------------------------------------------------
# No false positives on safe attribute access
# ---------------------------------------------------------------------------


class TestNoFalsePositives:
    """Safe attribute access on tracked module refs should not emit EXEC-002."""

    def test_json_loads_no_exec002(self) -> None:
        """m = __import__('json'); m.loads('{}') should NOT emit EXEC-002."""
        code = "m = __import__('json')\nm.loads('{}')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) == 0, f"Unexpected EXEC-002 for json.loads: {findings}"

    def test_os_path_no_exec002(self) -> None:
        """m = __import__('os'); m.path should NOT emit EXEC-002."""
        code = "m = __import__('os')\nm.path\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) == 0

    def test_os_getcwd_no_exec002(self) -> None:
        """m = __import__('os'); m.getcwd() should NOT emit EXEC-002."""
        code = "m = __import__('os')\nm.getcwd()\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PATH 2: func_ref assignment tracking (m.system stored as func_ref)
# ---------------------------------------------------------------------------


class TestFuncRefTracking:
    """f = m.system where m is tracked module should store func_ref in ref_table."""

    def test_func_ref_stored_in_ref_table(self) -> None:
        """m = __import__('os'); f = m.system -> ref_table has f as func_ref."""
        code = "m = __import__('os')\nf = m.system\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        ref_table = build_ref_table(tree, alias_map)

        # Now run detect_dynamic_exec which should mutate ref_table with func_ref
        symbol_table = build_symbol_table(tree)
        detect_dynamic_exec(
            tree,
            "test.py",
            alias_map,
            symbol_table,
            ref_table=ref_table,
        )

        # Check that ref_table now contains func_ref entry for 'f'
        assert "f" in ref_table, f"Expected 'f' in ref_table, got keys: {list(ref_table.keys())}"
        entry = ref_table["f"]
        assert entry.kind == "func_ref"
        assert entry.resolved == "os.system"

    def test_func_ref_scoped_in_function(self) -> None:
        """Inside a function, func_ref key should be scope-qualified."""
        code = "def exploit():\n    m = __import__('os')\n    f = m.system\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        ref_table = build_ref_table(tree, alias_map)

        symbol_table = build_symbol_table(tree)
        detect_dynamic_exec(
            tree,
            "test.py",
            alias_map,
            symbol_table,
            ref_table=ref_table,
        )

        # Function-scoped: key should be 'exploit.f'
        assert "exploit.f" in ref_table, (
            f"Expected 'exploit.f' in ref_table, got keys: {list(ref_table.keys())}"
        )
        entry = ref_table["exploit.f"]
        assert entry.kind == "func_ref"
        assert entry.resolved == "os.system"

    def test_func_ref_importlib_module(self) -> None:
        """mod = importlib.import_module('subprocess'); f = mod.call -> func_ref."""
        code = "import importlib\nmod = importlib.import_module('subprocess')\nf = mod.call\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        ref_table = build_ref_table(tree, alias_map)

        symbol_table = build_symbol_table(tree)
        detect_dynamic_exec(
            tree,
            "test.py",
            alias_map,
            symbol_table,
            ref_table=ref_table,
        )

        assert "f" in ref_table
        entry = ref_table["f"]
        assert entry.kind == "func_ref"
        assert entry.resolved == "subprocess.call"


# ---------------------------------------------------------------------------
# Function-scoped detection
# ---------------------------------------------------------------------------


class TestScopedDetection:
    """Depth-2 detection works inside function bodies."""

    def test_function_scoped_import_and_attr(self) -> None:
        """Depth-2 detection works inside a function scope."""
        code = "def exploit():\n    m = __import__('os')\n    m.system('whoami')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_class_scoped_import_and_attr(self) -> None:
        """Depth-2 detection works inside a class body."""
        code = "class Evil:\n    m = __import__('os')\n    m.system('whoami')\n"
        findings = _findings_by_rule(code, "EXEC-002")
        assert len(findings) >= 1
