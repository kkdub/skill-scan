"""Tests for text normalization module."""

from __future__ import annotations

import pytest

from skill_scan.normalizer import (
    canonicalize_whitespace,
    normalize_text,
    strip_zero_width,
)


class TestStripZeroWidth:
    """Tests for strip_zero_width — removal of invisible characters."""

    def test_removes_zero_width_space(self) -> None:
        assert strip_zero_width("e\u200bval") == "eval"

    def test_removes_zero_width_non_joiner(self) -> None:
        assert strip_zero_width("e\u200cval") == "eval"

    def test_removes_zero_width_joiner(self) -> None:
        assert strip_zero_width("e\u200dval") == "eval"

    def test_removes_word_joiner(self) -> None:
        assert strip_zero_width("e\u2060val") == "eval"

    def test_removes_byte_order_mark(self) -> None:
        assert strip_zero_width("\ufeffeval") == "eval"

    def test_removes_soft_hyphen(self) -> None:
        assert strip_zero_width("e\u00adval") == "eval"

    def test_removes_multiple_different_zero_width_chars(self) -> None:
        text = "e\u200bv\u200ca\u200dl\u2060(\ufeff)"
        assert strip_zero_width(text) == "eval()"

    def test_no_op_on_clean_text(self) -> None:
        clean = "eval(user_input)"
        assert strip_zero_width(clean) == clean

    def test_only_zero_width_chars(self) -> None:
        assert strip_zero_width("\u200b\u200c\u200d\u2060\ufeff\u00ad") == ""

    def test_preserves_newlines(self) -> None:
        text = "line1\u200b\nline2\u200c"
        assert strip_zero_width(text) == "line1\nline2"

    def test_preserves_tabs(self) -> None:
        text = "\te\u200bval"
        assert strip_zero_width(text) == "\teval"

    def test_multiple_adjacent_zero_width_chars(self) -> None:
        text = "e\u200b\u200c\u200dval"
        assert strip_zero_width(text) == "eval"


class TestCanonicalizeWhitespace:
    """Tests for canonicalize_whitespace — exotic space normalization."""

    def test_replaces_non_breaking_space(self) -> None:
        assert canonicalize_whitespace("a\u00a0b") == "a b"

    def test_replaces_en_quad(self) -> None:
        assert canonicalize_whitespace("a\u2000b") == "a b"

    def test_replaces_em_quad(self) -> None:
        assert canonicalize_whitespace("a\u2001b") == "a b"

    def test_replaces_en_space(self) -> None:
        assert canonicalize_whitespace("a\u2002b") == "a b"

    def test_replaces_em_space(self) -> None:
        assert canonicalize_whitespace("a\u2003b") == "a b"

    def test_replaces_three_per_em_space(self) -> None:
        assert canonicalize_whitespace("a\u2004b") == "a b"

    def test_replaces_four_per_em_space(self) -> None:
        assert canonicalize_whitespace("a\u2005b") == "a b"

    def test_replaces_six_per_em_space(self) -> None:
        assert canonicalize_whitespace("a\u2006b") == "a b"

    def test_replaces_figure_space(self) -> None:
        assert canonicalize_whitespace("a\u2007b") == "a b"

    def test_replaces_punctuation_space(self) -> None:
        assert canonicalize_whitespace("a\u2008b") == "a b"

    def test_replaces_thin_space(self) -> None:
        assert canonicalize_whitespace("a\u2009b") == "a b"

    def test_replaces_hair_space(self) -> None:
        assert canonicalize_whitespace("a\u200ab") == "a b"

    def test_replaces_narrow_no_break_space(self) -> None:
        assert canonicalize_whitespace("a\u202fb") == "a b"

    def test_replaces_medium_mathematical_space(self) -> None:
        assert canonicalize_whitespace("a\u205fb") == "a b"

    def test_replaces_ideographic_space(self) -> None:
        assert canonicalize_whitespace("a\u3000b") == "a b"

    def test_collapses_multiple_spaces_after_replacement(self) -> None:
        # Two exotic spaces become two regular spaces, then collapse to one
        assert canonicalize_whitespace("a\u00a0\u00a0b") == "a b"

    def test_collapses_mixed_regular_and_exotic_spaces(self) -> None:
        assert canonicalize_whitespace("a \u00a0 b") == "a b"

    def test_preserves_newlines(self) -> None:
        text = "line1\u00a0word\nline2"
        assert canonicalize_whitespace(text) == "line1 word\nline2"

    def test_preserves_tabs(self) -> None:
        text = "\tindented\u00a0word"
        assert canonicalize_whitespace(text) == "\tindented word"

    def test_no_op_on_clean_text(self) -> None:
        clean = "normal text here"
        assert canonicalize_whitespace(clean) == clean


class TestNormalizeText:
    """Tests for normalize_text — combined normalization pipeline."""

    def test_nfkc_fullwidth_eval(self) -> None:
        # Fullwidth Latin letters U+FF45 U+FF56 U+FF41 U+FF4C -> 'eval'
        assert normalize_text("\uff45\uff56\uff41\uff4c") == "eval"

    def test_nfkc_fullwidth_digits(self) -> None:
        # Fullwidth digits U+FF10-U+FF19 -> ASCII 0-9
        assert normalize_text("\uff11\uff12\uff13") == "123"

    def test_nfkc_fullwidth_exec(self) -> None:
        # Fullwidth 'exec' U+FF45 U+FF58 U+FF45 U+FF43
        assert normalize_text("\uff45\uff58\uff45\uff43") == "exec"

    def test_nfkc_fullwidth_import(self) -> None:
        # Fullwidth '__import__' with mixed ASCII and fullwidth
        assert normalize_text("__\uff49\uff4d\uff50\uff4f\uff52\uff54__") == "__import__"

    def test_nfkc_cjk_compatibility_char(self) -> None:
        # U+3231 (parenthesized ideograph stock) -> parenthesized form
        result = normalize_text("\u3231")
        assert "\u3231" not in result  # decomposed away from compatibility form

    def test_nfkc_runs_before_zero_width_strip(self) -> None:
        # NFKC first, then zero-width strip: fullwidth + zero-width combined
        text = "\uff45\u200b\uff56\u200c\uff41\u200d\uff4c"
        assert normalize_text(text) == "eval"

    def test_nfkc_runs_before_whitespace_canonicalize(self) -> None:
        # Fullwidth space U+3000 is NFKC-normalized to U+0020 (regular ASCII space)
        # canonicalize_whitespace is a no-op on it after that
        text = "\uff45\uff56\uff41\uff4c\u3000()"
        assert normalize_text(text) == "eval ()"

    def test_nfkc_combined_fullwidth_and_zero_width_and_exotic_space(self) -> None:
        # All three evasion tactics combined
        text = "\uff45\u200b\uff56\u200c\uff41\u200d\uff4c\u00a0()"
        assert normalize_text(text) == "eval ()"

    def test_nfkc_preserves_ascii_unchanged(self) -> None:
        # NFKC should be a no-op on plain ASCII
        assert normalize_text("eval(input)") == "eval(input)"

    def test_strips_zero_width_and_canonicalizes_whitespace(self) -> None:
        text = "e\u200bval\u00a0(input)"
        assert normalize_text(text) == "eval (input)"

    def test_identity_on_clean_text(self) -> None:
        clean = "normal code here"
        assert normalize_text(clean) == clean

    def test_preserves_newlines(self) -> None:
        text = "line1\u200b\nline2\u00a0word"
        assert normalize_text(text) == "line1\nline2 word"

    def test_preserves_tabs(self) -> None:
        text = "\t\u200beval\u00a0()"
        assert normalize_text(text) == "\teval ()"

    def test_combined_evasion_tactics(self) -> None:
        # Attacker uses zero-width + exotic spaces together
        text = "__\u200bimport\u200c__\u00a0(\u2003'os'\u2003)"
        assert normalize_text(text) == "__import__ ( 'os' )"

    def test_multiline_content_preserved(self) -> None:
        text = "line1\u200b\nline2\u200c\nline3\u00a0word"
        result = normalize_text(text)
        assert result.count("\n") == 2
        assert result == "line1\nline2\nline3 word"

    @pytest.mark.parametrize(
        "char,name",
        [
            ("\u200b", "ZWSP"),
            ("\u200c", "ZWNJ"),
            ("\u200d", "ZWJ"),
            ("\u2060", "WJ"),
            ("\ufeff", "BOM"),
            ("\u00ad", "soft-hyphen"),
        ],
    )
    def test_each_zero_width_char_stripped_in_pipeline(self, char: str, name: str) -> None:
        text = f"ev{char}al"
        assert normalize_text(text) == "eval", f"Failed for {name}"

    @pytest.mark.parametrize(
        "char,name",
        [
            ("\u00a0", "NBSP"),
            ("\u2000", "en-quad"),
            ("\u2003", "em-space"),
            ("\u202f", "narrow-NBSP"),
            ("\u205f", "math-space"),
            ("\u3000", "ideographic"),
        ],
    )
    def test_each_exotic_space_normalized_in_pipeline(self, char: str, name: str) -> None:
        text = f"a{char}b"
        assert normalize_text(text) == "a b", f"Failed for {name}"
