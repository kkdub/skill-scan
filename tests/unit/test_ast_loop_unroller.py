"""Tests for loop assembly static unrolling.

Covers collect_loop_assigns() resolution of
    target = ''
    for VAR in [str_literal, ...]:
        target += VAR
patterns, conservative rejection of unsupported variants,
and end-to-end corpus validation via analyze_python().
"""

from __future__ import annotations

import ast

from skill_scan._ast_loop_unroller import collect_loop_assigns
from skill_scan.ast_analyzer import analyze_python


_PARSE = ast.parse


# -- Basic resolution ---------------------------------------------------------


class TestLoopAssemblyBasic:
    """collect_loop_assigns resolves simple loop assembly patterns."""

    def test_inline_list_resolves_to_concatenation(self) -> None:
        """for c in ['e','v','a','l']: name += c -> name='eval'."""
        code = "name = ''\nfor c in ['e', 'v', 'a', 'l']:\n    name += c"
        result = collect_loop_assigns(_PARSE(code))
        assert result["name"] == "eval"

    def test_longer_string_assembly(self) -> None:
        """for c in ['h','e','l','l','o']: s += c -> s='hello'."""
        code = "s = ''\nfor c in ['h', 'e', 'l', 'l', 'o']:\n    s += c"
        result = collect_loop_assigns(_PARSE(code))
        assert result["s"] == "hello"

    def test_multichar_elements(self) -> None:
        """for part in ['ev','al']: name += part -> name='eval'."""
        code = "name = ''\nfor part in ['ev', 'al']:\n    name += part"
        result = collect_loop_assigns(_PARSE(code))
        assert result["name"] == "eval"

    def test_single_element_list(self) -> None:
        """for c in ['x']: s += c -> s='x'."""
        code = "s = ''\nfor c in ['x']:\n    s += c"
        result = collect_loop_assigns(_PARSE(code))
        assert result["s"] == "x"

    def test_empty_list_resolves_empty(self) -> None:
        """for c in []: s += c -> s=''."""
        code = "s = ''\nfor c in []:\n    s += c"
        result = collect_loop_assigns(_PARSE(code))
        assert result["s"] == ""


# -- Requires target initialization -------------------------------------------


class TestLoopAssemblyInitialization:
    """Target must be initialized to '' before the loop."""

    def test_no_init_returns_empty(self) -> None:
        """Missing target = '' before loop -> not resolved."""
        code = "for c in ['e', 'v', 'a', 'l']:\n    name += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result

    def test_init_to_nonempty_returns_none(self) -> None:
        """target = 'prefix' before loop -> not resolved (conservative)."""
        code = "name = 'x'\nfor c in ['e', 'v', 'a', 'l']:\n    name += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result

    def test_init_far_before_loop(self) -> None:
        """Init separated by other statements still resolves."""
        code = "name = ''\nx = 42\ny = 'hello'\nfor c in ['e', 'v', 'a', 'l']:\n    name += c"
        result = collect_loop_assigns(_PARSE(code))
        assert result["name"] == "eval"


# -- Iter source restrictions --------------------------------------------------


class TestLoopAssemblyIterSource:
    """Only inline list literals of string constants are supported."""

    def test_variable_iter_with_local_list_resolves(self) -> None:
        """for c in chars: ... where chars = [str, ...] in same scope -> resolved."""
        code = "chars = ['e', 'v', 'a', 'l']\nname = ''\nfor c in chars:\n    name += c"
        result = collect_loop_assigns(_PARSE(code))
        assert result["name"] == "eval"

    def test_variable_iter_unresolvable_not_supported(self) -> None:
        """for c in func(): ... where iter is a call -> not resolved."""
        code = "name = ''\nfor c in get_chars():\n    name += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result

    def test_non_string_elements_not_supported(self) -> None:
        """for c in [1, 2, 3]: s += c -> not resolved."""
        code = "s = ''\nfor c in [1, 2, 3]:\n    s += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "s" not in result

    def test_mixed_types_not_supported(self) -> None:
        """for c in ['a', 1, 'b']: s += c -> not resolved."""
        code = "s = ''\nfor c in ['a', 1, 'b']:\n    s += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "s" not in result

    def test_tuple_iter_not_supported(self) -> None:
        """for c in ('e','v','a','l'): name += c -> not resolved (tuple, not list)."""
        code = "name = ''\nfor c in ('e', 'v', 'a', 'l'):\n    name += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result

    def test_generator_iter_not_supported(self) -> None:
        """for c in (x for x in 'eval'): s += c -> not resolved."""
        code = "s = ''\nfor c in (x for x in 'eval'):\n    s += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "s" not in result


# -- Body restrictions --------------------------------------------------------


class TestLoopAssemblyBodyRestrictions:
    """Body must be exactly one AugAssign(target += loop_var)."""

    def test_multiple_body_statements_rejected(self) -> None:
        """Body with more than one statement -> not resolved."""
        code = "name = ''\nfor c in ['e', 'v', 'a', 'l']:\n    name += c\n    print(c)"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result

    def test_if_guard_in_body_rejected(self) -> None:
        """Body with if-guard -> not resolved (conservative)."""
        code = "name = ''\nfor c in ['e', 'v', 'a', 'l']:\n    if c != 'x':\n        name += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result

    def test_body_is_regular_assign_rejected(self) -> None:
        """Body with = instead of += -> not resolved."""
        code = "name = ''\nfor c in ['e', 'v', 'a', 'l']:\n    name = c"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result

    def test_augassign_different_variable_rejected(self) -> None:
        """target += loop_var where target != loop body var -> not resolved."""
        code = "name = ''\nfor c in ['e', 'v', 'a', 'l']:\n    other += c"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result
        assert "other" not in result

    def test_augassign_not_add_rejected(self) -> None:
        """target *= loop_var -> not resolved (only += supported)."""
        code = "name = ''\nfor c in ['e', 'v', 'a', 'l']:\n    name *= c"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result


# -- Nested loops --------------------------------------------------------------


class TestLoopAssemblyNestedLoops:
    """Nested loops are not supported (single-level only)."""

    def test_nested_loop_outer_not_resolved(self) -> None:
        """Outer loop with nested inner loop -> not resolved."""
        code = "name = ''\nfor c in ['e', 'v', 'a', 'l']:\n    name += c\n    for x in ['a']:\n        pass"
        result = collect_loop_assigns(_PARSE(code))
        assert "name" not in result


# -- Function-level scope -----------------------------------------------------


class TestLoopAssemblyFunctionScope:
    """collect_loop_assigns handles function-level bodies."""

    def test_loop_inside_function(self) -> None:
        """Loop assembly inside a function resolves."""
        code = (
            "def build():\n"
            "    name = ''\n"
            "    for c in ['e', 'v', 'a', 'l']:\n"
            "        name += c\n"
            "    return name\n"
        )
        result = collect_loop_assigns(_PARSE(code))
        assert any(v == "eval" for v in result.values())

    def test_multiple_loops_resolved(self) -> None:
        """Multiple loop patterns each resolved independently."""
        code = "a = ''\nfor c in ['e', 'v']:\n    a += c\nb = ''\nfor c in ['a', 'l']:\n    b += c\n"
        result = collect_loop_assigns(_PARSE(code))
        assert result["a"] == "ev"
        assert result["b"] == "al"


# -- End-to-end integration ---------------------------------------------------


class TestLoopAssemblyEndToEnd:
    """Integration with analyze_python via symbol table merge."""

    def test_loop_assembly_produces_exec002(self) -> None:
        """Loop-assembled 'eval' used in globals()[name]() triggers EXEC-002."""
        code = "name = ''\nfor c in ['e', 'v', 'a', 'l']:\n    name += c\nglobals()[name]('print(1)')\n"
        findings = analyze_python(code, "test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "EXEC-002" in rule_ids


# -- Corpus validation --------------------------------------------------------


class TestCorpusLoopAssembly:
    """Inlined corpus: loop_assembly.py produces EXEC-002."""

    _CORPUS_CODE = (
        "chars = ['e', 'v', 'a', 'l']\n"
        "name = ''\n"
        "for c in chars:\n"
        "    name += c\n"
        "globals()[name](\"print('pwned')\")\n"
    )

    def test_corpus_loop_assembly_produces_exec002(self) -> None:
        """R007: corpus loop_assembly.py produces EXEC-002 finding."""
        findings = analyze_python(self._CORPUS_CODE, "loop_assembly.py")
        rule_ids = [f.rule_id for f in findings]
        assert "EXEC-002" in rule_ids
