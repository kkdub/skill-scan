"""Tests for Part B: multiline PI extraction and string resolution extraction.

Verifies:
- R003: _multiline_pi.py exists, is importable, and engine.py delegates to it
- R004: _ast_string_resolver.py exists, absorbs former _ast_join_helpers.py functions,
        _ast_imports.py re-exports point to new module
- R-IMP001: Zero behavioral changes (existing tests cover behavior; these
           test structural invariants)
- R-IMP002: Facade re-exports stable
- R-IMP003: No orphaned imports (ruff catches this; structural tests here)
- R-IMP004: No file exceeds 300 lines
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib


# ---------------------------------------------------------------------------
# R003: Multiline PI extraction
# ---------------------------------------------------------------------------


class TestMultilinePIExtraction:
    """Verify _multiline_pi.py exists and engine.py delegates to it."""

    def test_multiline_pi_module_exists(self) -> None:
        """rules/_multiline_pi.py is importable."""
        mod = importlib.import_module("skill_scan.rules._multiline_pi")
        assert hasattr(mod, "_multiline_pi_findings")

    def test_multiline_pi_findings_callable(self) -> None:
        """_multiline_pi_findings is a callable with expected signature."""
        from skill_scan.rules._multiline_pi import _multiline_pi_findings

        sig = inspect.signature(_multiline_pi_findings)
        param_names = list(sig.parameters.keys())
        # Must accept lines, file_path, pi_rules, existing, make_finding, is_excluded
        assert "lines" in param_names
        assert "file_path" in param_names
        assert "pi_rules" in param_names
        assert "existing" in param_names
        assert "make_finding" in param_names
        assert "is_excluded" in param_names

    def test_scan_window_rule_callable(self) -> None:
        """_scan_window_rule is a callable in _multiline_pi module."""
        from skill_scan.rules._multiline_pi import _scan_window_rule

        sig = inspect.signature(_scan_window_rule)
        param_names = list(sig.parameters.keys())
        assert "make_finding" in param_names
        assert "is_excluded" in param_names

    def test_engine_delegates_to_multiline_pi(self) -> None:
        """engine._line_phase_findings still produces multiline PI findings.

        This is an integration check that the delegation works end-to-end.
        """
        from skill_scan.models import Severity
        from skill_scan.rules.engine import match_content
        from tests.unit.rule_helpers import make_rule

        rule = make_rule(
            rule_id="PI-001",
            severity=Severity.CRITICAL,
            category="prompt-injection",
            patterns=[r"(?i)ignore\s+previous\s+instructions"],
        )
        content = "ignore\nprevious\ninstructions"
        findings = match_content(content, "test.md", [rule])
        pi_findings = [f for f in findings if f.rule_id == "PI-001"]
        assert len(pi_findings) >= 1

    def test_engine_py_line_count(self) -> None:
        """engine.py is <=265 lines after extraction."""
        engine_path = (
            pathlib.Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "engine.py"
        )
        line_count = len(engine_path.read_text(encoding="utf-8").splitlines())
        assert line_count <= 265, f"engine.py has {line_count} lines, expected <=265"

    def test_multiline_pi_line_count(self) -> None:
        """_multiline_pi.py is <=80 lines."""
        mp_path = (
            pathlib.Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "_multiline_pi.py"
        )
        line_count = len(mp_path.read_text(encoding="utf-8").splitlines())
        assert line_count <= 80, f"_multiline_pi.py has {line_count} lines, expected <=80"

    def test_multiline_pi_only_imports_models(self) -> None:
        """_multiline_pi.py imports only from models (no circular engine import)."""
        mp_path = (
            pathlib.Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "rules" / "_multiline_pi.py"
        )
        source = mp_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "engine" not in node.module, "_multiline_pi.py must not import from engine (circular)"


# ---------------------------------------------------------------------------
# R004: String resolution extraction
# ---------------------------------------------------------------------------


class TestStringResolverExtraction:
    """Verify _ast_string_resolver.py exists and contains extracted functions."""

    def test_string_resolver_module_exists(self) -> None:
        """_ast_string_resolver.py is importable."""
        mod = importlib.import_module("skill_scan._ast_string_resolver")
        assert mod is not None

    def test_string_resolver_has_expected_functions(self) -> None:
        """_ast_string_resolver.py exports all extracted functions."""
        from skill_scan import _ast_string_resolver

        expected = [
            "MAX_AST_RESOLVE_DEPTH",
            "try_resolve_string",
            "_try_resolve_string",
            "_resolve_binop_add",
            "_resolve_int_expr",
            "_resolve_chr_call",
            "_resolve_join_call",
            "_resolve_iterable_elements",
            "_resolve_bytes_decode",
            "_get_call_name_from_any",
            # Absorbed from _ast_join_helpers:
            "_resolve_int_list_to_chars",
            "_is_chr_of_target",
            "_resolve_join_listcomp",
            "_resolve_join_map_chr",
        ]
        for name in expected:
            assert hasattr(_ast_string_resolver, name), f"_ast_string_resolver missing {name}"

    def test_max_resolve_depth_value(self) -> None:
        """MAX_AST_RESOLVE_DEPTH is 50."""
        from skill_scan._ast_string_resolver import MAX_AST_RESOLVE_DEPTH

        assert MAX_AST_RESOLVE_DEPTH == 50

    def test_ast_join_helpers_deleted(self) -> None:
        """_ast_join_helpers.py no longer exists on disk."""
        join_path = (
            pathlib.Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "_ast_join_helpers.py"
        )
        assert not join_path.exists(), "_ast_join_helpers.py should be deleted"

    def test_ast_imports_line_count(self) -> None:
        """_ast_imports.py (was _ast_helpers.py) is <=160 lines after extraction."""
        helpers_path = pathlib.Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "_ast_imports.py"
        line_count = len(helpers_path.read_text(encoding="utf-8").splitlines())
        assert line_count <= 160, f"_ast_imports.py has {line_count} lines, expected <=160"

    def test_string_resolver_line_count(self) -> None:
        """_ast_string_resolver.py is <=200 lines."""
        resolver_path = (
            pathlib.Path(__file__).resolve().parents[2] / "src" / "skill_scan" / "_ast_string_resolver.py"
        )
        line_count = len(resolver_path.read_text(encoding="utf-8").splitlines())
        assert line_count <= 200, f"_ast_string_resolver.py has {line_count} lines, expected <=200"


# ---------------------------------------------------------------------------
# R-IMP002: Facade re-exports stable
# ---------------------------------------------------------------------------


class TestFacadeReExports:
    """Verify backward-compatible re-exports from _ast_helpers.py."""

    def test_ast_helpers_reexports_string_resolver_functions(self) -> None:
        """_ast_helpers still re-exports all string resolution functions."""
        from skill_scan._ast_imports import (
            MAX_AST_RESOLVE_DEPTH,
            _get_call_name_from_any,
            _is_chr_of_target,
            _resolve_binop_add,
            _resolve_bytes_decode,
            _resolve_chr_call,
            _resolve_int_expr,
            _resolve_int_list_to_chars,
            _resolve_iterable_elements,
            _resolve_join_call,
            _resolve_join_listcomp,
            _resolve_join_map_chr,
            _try_resolve_string,
            try_resolve_string,
        )

        # Verify they resolve to the canonical _ast_string_resolver module
        from skill_scan import _ast_string_resolver

        assert try_resolve_string is _ast_string_resolver.try_resolve_string
        assert _try_resolve_string is _ast_string_resolver._try_resolve_string
        assert _resolve_binop_add is _ast_string_resolver._resolve_binop_add
        assert _resolve_int_expr is _ast_string_resolver._resolve_int_expr
        assert _resolve_chr_call is _ast_string_resolver._resolve_chr_call
        assert _resolve_join_call is _ast_string_resolver._resolve_join_call
        assert _resolve_iterable_elements is _ast_string_resolver._resolve_iterable_elements
        assert _resolve_bytes_decode is _ast_string_resolver._resolve_bytes_decode
        assert _get_call_name_from_any is _ast_string_resolver._get_call_name_from_any
        assert _resolve_int_list_to_chars is _ast_string_resolver._resolve_int_list_to_chars
        assert _is_chr_of_target is _ast_string_resolver._is_chr_of_target
        assert _resolve_join_listcomp is _ast_string_resolver._resolve_join_listcomp
        assert _resolve_join_map_chr is _ast_string_resolver._resolve_join_map_chr
        assert MAX_AST_RESOLVE_DEPTH == 50

    def test_ast_helpers_retains_own_functions(self) -> None:
        """_ast_helpers.py still has its own non-extracted functions."""
        from skill_scan._ast_imports import (
            build_alias_map,
            get_call_name,
            has_safe_loader,
            is_subprocess_shell_true,
        )

        assert callable(build_alias_map)
        assert callable(get_call_name)
        assert callable(is_subprocess_shell_true)
        assert callable(has_safe_loader)


# ---------------------------------------------------------------------------
# R004 behavioral: string resolver works end-to-end
# ---------------------------------------------------------------------------


class TestStringResolverBehavior:
    """Verify extracted functions still work correctly (behavioral regression)."""

    def test_try_resolve_string_constant(self) -> None:
        """Resolves string constant."""
        from skill_scan._ast_string_resolver import try_resolve_string

        node = ast.Constant(value="hello")
        assert try_resolve_string(node) == "hello"

    def test_try_resolve_string_binop(self) -> None:
        """Resolves string concatenation."""
        from skill_scan._ast_string_resolver import try_resolve_string

        tree = ast.parse("'ev' + 'al'", mode="eval")
        assert try_resolve_string(tree.body) == "eval"

    def test_try_resolve_string_chr(self) -> None:
        """Resolves chr(N) calls."""
        from skill_scan._ast_string_resolver import try_resolve_string

        tree = ast.parse("chr(101)", mode="eval")
        assert try_resolve_string(tree.body) == "e"

    def test_try_resolve_string_join(self) -> None:
        """Resolves join on list of strings."""
        from skill_scan._ast_string_resolver import try_resolve_string

        tree = ast.parse("''.join(['e', 'v', 'a', 'l'])", mode="eval")
        assert try_resolve_string(tree.body) == "eval"

    def test_try_resolve_string_bytes_decode(self) -> None:
        """Resolves bytes decode."""
        from skill_scan._ast_string_resolver import try_resolve_string

        tree = ast.parse("b'eval'.decode()", mode="eval")
        assert try_resolve_string(tree.body) == "eval"

    def test_resolve_int_list_to_chars(self) -> None:
        """Resolves int list to chr characters."""
        from skill_scan._ast_string_resolver import _resolve_int_list_to_chars

        elts = [ast.Constant(value=v) for v in [101, 118, 97, 108]]
        assert _resolve_int_list_to_chars(elts, "") == "eval"

    def test_resolve_join_listcomp(self) -> None:
        """Resolves join with list comprehension."""
        from skill_scan._ast_string_resolver import _resolve_join_listcomp

        tree = ast.parse("[chr(c) for c in [101, 118, 97, 108]]", mode="eval")
        listcomp = tree.body
        assert isinstance(listcomp, ast.ListComp)
        assert _resolve_join_listcomp(listcomp, "") == "eval"

    def test_resolve_join_map_chr(self) -> None:
        """Resolves join with map(chr, [...])."""
        from skill_scan._ast_string_resolver import _resolve_join_map_chr

        tree = ast.parse("map(chr, [101, 118, 97, 108])", mode="eval")
        call = tree.body
        assert isinstance(call, ast.Call)
        assert _resolve_join_map_chr(call, "") == "eval"

    def test_resolve_int_expr_arithmetic(self) -> None:
        """Resolves integer arithmetic."""
        from skill_scan._ast_string_resolver import _resolve_int_expr

        tree = ast.parse("100 + 1", mode="eval")
        assert _resolve_int_expr(tree.body) == 101

    def test_is_chr_of_target(self) -> None:
        """Checks chr(target) detection."""
        from skill_scan._ast_string_resolver import _is_chr_of_target

        tree = ast.parse("[chr(c) for c in [101]]", mode="eval")
        listcomp = tree.body
        assert isinstance(listcomp, ast.ListComp)
        assert _is_chr_of_target(listcomp.elt, "c")
        assert not _is_chr_of_target(listcomp.elt, "x")

    def test_depth_limit_returns_none(self) -> None:
        """Exceeding MAX_AST_RESOLVE_DEPTH returns None."""
        from skill_scan._ast_string_resolver import _try_resolve_string

        node = ast.Constant(value="hello")
        assert _try_resolve_string(node, _depth=51) is None


# ---------------------------------------------------------------------------
# R-IMP004: No file exceeds 300 lines
# ---------------------------------------------------------------------------


class TestNoFileExceeds300Lines:
    """Verify no src/ file exceeds 300 lines."""

    def test_no_src_file_exceeds_300_lines(self) -> None:
        """All .py files in src/skill_scan/ are <=300 lines."""
        src_dir = pathlib.Path(__file__).resolve().parents[2] / "src" / "skill_scan"
        violations = []
        for py_file in src_dir.rglob("*.py"):
            line_count = len(py_file.read_text(encoding="utf-8").splitlines())
            if line_count > 300:
                violations.append(f"{py_file.name}: {line_count} lines")
        assert not violations, f"Files exceeding 300 lines: {violations}"
