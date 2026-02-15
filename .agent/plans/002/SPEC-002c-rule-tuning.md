# SPEC-002c: Rule Tuning (PI-004, PI-005, PI-006)

## Problem

Testing against 34 real-world skills revealed high false-positive rates in three
medium-severity rules. The rules detect the right *category* of concern but lack
context to distinguish benign from suspicious content.

### PI-004: Hidden Unicode (zero-width characters)

- **False positives**: Zero-width spaces (`U+200B`) are legitimate in CJK text
  as word-break hints. Web-scraped reference docs commonly contain them.
- **Example**: `niko91i_Skills-Vendure` — 7,295 hits, all from Vendure
  documentation reference files with copy-pasted web content.

### PI-005: HTML comment injection

- **False positives**: `<!--.*-->` matches ALL HTML comments, including standard
  template comments like `<!-- Chart.js CDN -->`, `<!-- Key Metrics -->`.
- **Example**: `shanselman_nightscout-cgm-skill` — 21 hits, all standard HTML
  section markers in generated HTML.

### PI-006: Steganographic encoding

- **False positives**: `(\\x[0-9a-fA-F]{2}){4,}` matches hex escape sequences
  in test scripts and binary format handlers.
- **Example**: `Dicklesworthstone_repo_updater` — BOM test data
  (`\x00\xFF\xFE\x01`) in a shell test script.

## Requirements

### RT1: PI-004 — Context-aware Unicode detection

Reduce false positives while preserving detection of genuinely suspicious
zero-width characters.

**Approach: Rule split + path exclusions (Option B + A hybrid)**

Split PI-004 into two rules with different severities, and add path exclusions.

**Note**: Path-based exclusions require a small engine extension. The current
`Rule` model and `match_line()` engine only support line-text exclude patterns
(`exclude_patterns` field). To support path exclusions, add a
`path_exclude_patterns` field to the `Rule` model and a path check in the
scanner's per-file loop (before calling `match_line`). This is a targeted
change to `models.py`, `loader.py`, and `scanner.py` — not a full engine
rewrite.

**PI-004a: Directional overrides** (severity: `medium`)
- Patterns: `[\u202A-\u202E]`
- No exclusions — directional overrides are almost never legitimate and can
  reorder visible text to hide malicious intent.
- Stays at `medium` because it affects the verdict (FLAG).

**PI-004b: Zero-width characters** (severity: `info`)
- Patterns: `[\u200B\u200C\u200D\u2060\uFEFF]`
- Demoted to `info` because zero-width chars are often legitimate in CJK text
  (word-break hints), web-scraped docs, and copy-pasted content.
- At `info` severity, these findings are observable but do not affect the
  verdict (PASS verdict preserved).
- Path exclusion: skip files under `references/` directories (scraped web
  content that the skill does not inject into agent context).

**Why not Option C (density check)?** It's the most precise solution but
requires engine changes to make `match_line` context-aware. The B+A combo
is simpler and, combined with SPEC-002d's output deduplication, keeps the
output manageable. Option C can be revisited if noise remains too high.

### RT2: PI-005 — Semantic HTML comment filtering

Reduce false positives by excluding obviously benign HTML comments.

**Approach: Expanded exclude patterns**

Add exclude patterns for common benign comment patterns:
- Standard HTML section markers: `<!--\s*(Header|Footer|Nav|Sidebar|Main|Content|Section|Container)\b`
- Framework markers: `<!--\s*(CDN|Script|Style|Link|Meta)\b`
- Template markers: `<!--\s*(Begin|End|Start|Stop)\b`
- Measurement/data labels: `<!--\s*(Chart|Graph|Table|Grid|List|Row|Column|Cell|Metric|Summary|Total|Count)\b`
- Layout markers: `<!--\s*(Wrapper|Inner|Outer|Left|Right|Top|Bottom)\b`
- Common patterns: `<!--\s*(Copyright|License|Generated|Auto-generated|DO NOT EDIT)\b`

Keep detection for:
- Comments containing instruction-like language: `<!--.*\b(ignore|override|system|prompt|instruction|execute|eval)\b.*-->`
- Multi-line unclosed comments (`<!--[^>]*$`) — these can hide content from
  rendered views.

### RT3: PI-006 — Steganographic encoding refinement

Reduce false positives on hex escapes in test/config contexts.

**Approach: Context exclusions**

- Exclude hex escapes in `.sh` and `.py` files that are in `test` directories
  or files with `test` in the name — test data commonly uses raw bytes.
- Exclude hex escapes that match known byte-order marks: `\\x00\\xFF\\xFE`,
  `\\xEF\\xBB\\xBF`, `\\xFF\\xFE`.
- Exclude the `aWdub3Jl` base64 pattern check (this is "ignore" in base64 —
  too specific and easily evaded by prepending a single byte).
- Tighten the long base64 pattern: require 200+ chars instead of 100+ to reduce
  matches on legitimate encoded content (e.g. embedded images, font data).

### RT4: Test corpus validation

After tuning, re-run against the 34-skill test corpus and verify:
- `cskwork_pptx-to-html-updated`: should PASS (CDN comment is benign).
- `Dicklesworthstone_repo_updater`: should PASS (BOM test data is benign).
- `Ketomihine_my_skills`: finding count should drop significantly.
- `niko91i_Skills-Vendure`: finding count should drop from 7,295 to a
  reasonable number (or PASS if all are reference doc artifacts).
- `shanselman_nightscout-cgm-skill`: finding count should drop significantly.
- No new false negatives: existing positive test cases must still trigger.

## Files Affected

| File | Change |
|------|--------|
| `src/skill_scan/rules/data/prompt_injection.toml` | Updated patterns and exclude_patterns for PI-004, PI-005, PI-006 |
| `src/skill_scan/models.py` | Add `path_exclude_patterns` field to `Rule` dataclass |
| `src/skill_scan/rules/loader.py` | Parse `path_exclude_patterns` from TOML |
| `src/skill_scan/scanner.py` | Check path_exclude_patterns before scanning each file against a rule |
| `tests/unit/test_rules_prompt_injection_detection.py` | Updated tests for PI-004a/PI-004b split, PI-005 exclusions |
| `tests/unit/test_rules_prompt_injection_encoding.py` | Updated tests for PI-006 exclusions |
| `tests/unit/test_rules_prompt_injection_evasion.py` | Verify no regressions in evasion detection |
| `tests/` | Regression tests against known false-positive cases |

## Acceptance Criteria

- PI-004 does not flag isolated zero-width chars in CJK reference documents.
- PI-004 still flags zero-width chars inserted between ASCII letters.
- PI-005 does not flag standard HTML section/template comments.
- PI-005 still flags comments containing instruction-like keywords.
- PI-006 does not flag BOM sequences or hex escapes in test files.
- PI-006 still flags genuinely suspicious long base64 or hex payloads.
- All existing positive detection tests still pass (no new false negatives).
- Test corpus re-validation documented.

## Out of Scope

- New rules (covered in future plans for R4-R7).
- Engine architecture changes beyond what's needed for path-aware exclusions.
