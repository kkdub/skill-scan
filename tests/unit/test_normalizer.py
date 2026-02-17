"""Tests for text normalization module."""

from __future__ import annotations

import pytest

from skill_scan.normalizer import (
    canonicalize_whitespace,
    normalize_line,
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

    def test_empty_string(self) -> None:
        assert strip_zero_width("") == ""

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

    def test_empty_string(self) -> None:
        assert canonicalize_whitespace("") == ""


class TestNormalizeLine:
    """Tests for normalize_line — combined normalization pipeline."""

    def test_strips_zero_width_and_canonicalizes_whitespace(self) -> None:
        text = "e\u200bval\u00a0(input)"
        assert normalize_line(text) == "eval (input)"

    def test_identity_on_clean_text(self) -> None:
        clean = "normal code here"
        assert normalize_line(clean) == clean

    def test_empty_string(self) -> None:
        assert normalize_line("") == ""

    def test_preserves_newlines(self) -> None:
        text = "line1\u200b\nline2\u00a0word"
        assert normalize_line(text) == "line1\nline2 word"

    def test_preserves_tabs(self) -> None:
        text = "\t\u200beval\u00a0()"
        assert normalize_line(text) == "\teval ()"

    def test_combined_evasion_tactics(self) -> None:
        # Attacker uses zero-width + exotic spaces together
        text = "__\u200bimport\u200c__\u00a0(\u2003'os'\u2003)"
        assert normalize_line(text) == "__import__ ( 'os' )"

    def test_multiline_content_preserved(self) -> None:
        text = "line1\u200b\nline2\u200c\nline3\u00a0word"
        result = normalize_line(text)
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
        assert normalize_line(text) == "eval", f"Failed for {name}"

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
        assert normalize_line(text) == "a b", f"Failed for {name}"
