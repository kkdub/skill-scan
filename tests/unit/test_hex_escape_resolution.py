"""Tests for hex escape-sequence resolution (Part E of PLAN-032).

Covers:
- R009: hex whitespace stripping via .replace() chain on tracked variable
- Symbol table resolves .replace() chain on tracked hex string variable
- bytes.fromhex(tracked_var) resolves when tracked_var is clean hex string
- Existing hex decoding unchanged (no regression on space-separated hex)
- Corpus decoder_hex_spaced.py pattern produces OBFS-004 or EXEC-002 finding
"""

from __future__ import annotations

import ast
import pathlib
import textwrap

from skill_scan._ast_split_detector import detect_split_evasion
from skill_scan._ast_symbol_table import build_symbol_table
from skill_scan.ast_analyzer import analyze_python
from skill_scan.models import Finding

_PARSE = ast.parse
_FILE = "test.py"


def _detect(code: str) -> list[Finding]:
    """Helper: parse code, build symbol table, run split detector."""
    tree = _PARSE(code)
    st = build_symbol_table(tree)
    return detect_split_evasion(tree, _FILE, {}, st)


def _corpus_code() -> str:
    """Build source code matching corpus decoder_hex_spaced.py pattern.

    The corpus file contains literal backslash-t and backslash-n in source,
    which Python interprets as escape sequences (tab and newline chars).
    """
    corpus = (
        pathlib.Path(__file__).resolve().parent.parent
        / "corpus"
        / "red-team"
        / "2026-03-17-full"
        / "exfil-obfs-evasion"
        / "decoder_hex_spaced.py"
    )
    if corpus.exists():
        return corpus.read_text()
    # Fallback: construct equivalent source with escape sequences
    # hex_str = '65\t76\n61\t6c' where \t/\n are Python escape sequences
    return (
        "hex_str = '65\\t76\\n61\\t6c'\n"
        "clean = hex_str.replace('\\t', '').replace('\\n', '')\n"
        "name = bytes.fromhex(clean).decode()\n"
        "globals()[name](\"print('pwned')\")\n"
    )


# -- R009: Hex escape-sequence resolution via variable propagation -----------


class TestHexEscapeVariablePropagation:
    """Symbol table should propagate .replace() chain on hex string variables."""

    def test_replace_chain_strips_chars_from_hex_variable(self) -> None:
        """Variable-base .replace() chain tracked in symbol table."""
        code = textwrap.dedent("""\
            base = "syZZem"
            name = base.replace("ZZ", "st")
        """)
        tree = _PARSE(code)
        st = build_symbol_table(tree)
        # name should resolve to 'system' after .replace() chain
        assert st.get("name") == "system"

    def test_replace_chain_two_step_variable_base(self) -> None:
        """Two-step .replace() on tracked variable resolves."""
        code = textwrap.dedent("""\
            raw = "eXYl"
            clean = raw.replace("X", "va").replace("Y", "")
        """)
        tree = _PARSE(code)
        st = build_symbol_table(tree)
        assert st.get("clean") == "eval"

    def test_replace_chain_stripping_separators(self) -> None:
        """Stripping separator chars from hex string tracked in symbol table."""
        # Use non-escape separator (dash) for simplicity
        code = textwrap.dedent("""\
            hex_str = "65-76-61-6c"
            clean = hex_str.replace("-", "")
        """)
        tree = _PARSE(code)
        st = build_symbol_table(tree)
        assert st.get("clean") == "6576616c"


class TestFromhexTrackedVariable:
    """bytes.fromhex(tracked_var) should resolve via symbol table lookup."""

    def test_fromhex_tracked_var_decode_eval(self) -> None:
        """bytes.fromhex(var).decode() where var resolves to '6576616c' -> 'eval'."""
        code = textwrap.dedent("""\
            hex_str = "6576616c"
            name = bytes.fromhex(hex_str).decode()
        """)
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "OBFS-004")]
        assert len(exec_findings) >= 1

    def test_fromhex_tracked_var_decode_system(self) -> None:
        """bytes.fromhex(tracked).decode() building 'system' detected."""
        code = textwrap.dedent("""\
            h = "73797374656d"
            name = bytes.fromhex(h).decode()
        """)
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_fromhex_replace_chain_var(self) -> None:
        """Full pattern: hex var -> replace chain -> bytes.fromhex(clean).decode()."""
        code = textwrap.dedent("""\
            hex_str = "65-76-61-6c"
            clean = hex_str.replace("-", "")
            name = bytes.fromhex(clean).decode()
        """)
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "OBFS-004")]
        assert len(exec_findings) >= 1

    def test_fromhex_untracked_var_no_crash(self) -> None:
        """bytes.fromhex(unknown_var).decode() does not crash."""
        code = "name = bytes.fromhex(unknown_var).decode()"
        findings = _detect(code)
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "OBFS-004")]
        assert len(dangerous) == 0

    def test_fromhex_tracked_var_safe_no_finding(self) -> None:
        """bytes.fromhex(var).decode() with safe content produces no finding."""
        code = textwrap.dedent("""\
            h = "68656c6c6f"
            name = bytes.fromhex(h).decode()
        """)
        findings = _detect(code)
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "OBFS-004", "EXEC-006")]
        assert len(dangerous) == 0

    def test_fromhex_tracked_import_produces_exec006(self) -> None:
        """bytes.fromhex(var).decode() building __import__ produces EXEC-006."""
        code = textwrap.dedent("""\
            h = "5f5f696d706f72745f5f"
            name = bytes.fromhex(h).decode()
        """)
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-006"]
        assert len(exec_findings) >= 1


class TestHexEscapeNoRegression:
    """Existing hex decoding must not regress."""

    def test_inline_fromhex_still_works(self) -> None:
        """Inline bytes.fromhex('6576616c').decode() still detected."""
        code = "name = bytes.fromhex('6576616c').decode()"
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_fromhex_concat_still_works(self) -> None:
        """(bytes.fromhex('XX') + bytes.fromhex('YY')).decode() still works."""
        code = "name = (bytes.fromhex('6576') + bytes.fromhex('616c')).decode()"
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_replace_chain_literal_base_still_works(self) -> None:
        """Literal-base .replace() chain unchanged."""
        code = "name = 'eXYl'.replace('X', 'va').replace('Y', '')"
        findings = _detect(code)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1

    def test_safe_replace_no_false_positive(self) -> None:
        """Safe .replace() still produces no finding."""
        code = "msg = 'hello world'.replace('world', 'there')"
        findings = _detect(code)
        dangerous = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006")]
        assert len(dangerous) == 0


class TestCorpusHexSpacedPattern:
    """Corpus decoder_hex_spaced.py pattern produces finding."""

    def test_corpus_file_produces_finding(self) -> None:
        """Actual corpus file with tab/newline hex separators detected."""
        code = _corpus_code()
        findings = analyze_python(code, _FILE)
        relevant = [f for f in findings if f.rule_id in ("EXEC-002", "OBFS-004")]
        assert len(relevant) >= 1

    def test_simple_hex_var_via_analyze_python(self) -> None:
        """analyze_python on simple hex variable pattern detects evasion."""
        code = textwrap.dedent("""\
            hex_str = "6576616c"
            name = bytes.fromhex(hex_str).decode()
        """)
        findings = analyze_python(code, _FILE)
        relevant = [f for f in findings if f.rule_id in ("EXEC-002", "OBFS-004")]
        assert len(relevant) >= 1


# -- Acceptance scenarios (plan-level, final feature part) -------------------


class TestAcceptanceIntListConcat:
    """Acceptance: int-list concat evasion detected (Part A)."""

    def test_int_list_concat_produces_exec_002(self) -> None:
        code = textwrap.dedent("""\
            part1 = [101, 118]
            part2 = [97, 108]
            codes = part1 + part2
            exec(''.join(chr(c) for c in codes))
        """)
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1


class TestAcceptanceStarUnpackJoin:
    """Acceptance: star-unpack join evasion detected (Part C)."""

    def test_star_unpack_join_produces_exec_002(self) -> None:
        code = textwrap.dedent("""\
            parts1 = ['ev', 'al']
            name = ''.join([*parts1])
        """)
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1


class TestAcceptanceDictPop:
    """Acceptance: dict.pop evasion detected (Part D)."""

    def test_dict_pop_produces_exec_002(self) -> None:
        code = textwrap.dedent("""\
            funcs = {'target': 'eval', 'decoy': 'print'}
            name = funcs.pop('target')
            globals()[name]("print('pwned')")
        """)
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec_findings) >= 1


class TestAcceptanceKwargsDynamicKey:
    """Acceptance: kwargs dynamic key detected (Part B)."""

    def test_kwargs_dynamic_key_produces_finding(self) -> None:
        code = textwrap.dedent("""\
            import subprocess
            key = 'sh' + 'ell'
            opts = {key: True}
            subprocess.run(['echo', 'hello'], **opts)
        """)
        findings = analyze_python(code, _FILE)
        relevant = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-005")]
        assert len(relevant) >= 1


class TestAcceptanceHexEscape:
    """Acceptance: hex escape-sequence evasion detected (Part E)."""

    def test_hex_escape_produces_finding(self) -> None:
        code = textwrap.dedent("""\
            hex_str = "6576616c"
            clean = hex_str.replace("-", "")
            name = bytes.fromhex(clean).decode()
        """)
        findings = analyze_python(code, _FILE)
        relevant = [f for f in findings if f.rule_id in ("EXEC-002", "OBFS-004")]
        assert len(relevant) >= 1
