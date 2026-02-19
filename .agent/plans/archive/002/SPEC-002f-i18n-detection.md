# SPEC-002f: Internationalization / Multilingual Detection

## Problem

All prompt injection detection rules (PI-001 through PI-003) use English-only
patterns. A skill containing `忽略之前的指令` ("ignore previous instructions"
in Chinese) or `ignoriere vorherige Anweisungen` (German) passes the scanner
undetected.

From the 34-skill test corpus:
- `tanweai_xianzhi-research` — Chinese security research skill, passed cleanly.
- `muyen_meihua-yishu` — Chinese art skill, passed cleanly.
- `DophinL_ruanyifeng-weekly-skill` — Chinese newsletter skill, passed cleanly.

We cannot know whether these are genuinely safe or contain non-English injection
patterns that we're blind to. This is a gap in coverage that grows as the skill
ecosystem internationalizes.

## Analysis

### Scope of the problem

Prompt injection works because LLMs understand natural language. LLMs are
multilingual — they follow instructions in Chinese, Spanish, Arabic, Russian,
Japanese, Korean, German, French, and dozens of other languages. An attacker
can use any language the target model understands.

### Approaches considered

1. **Translate all patterns into N languages** — Combinatorial explosion.
   PI-001 has 6 patterns; with 10 languages that's 60 patterns per rule, with
   linguistic nuances making direct translation unreliable.

2. **Use an LLM to classify content** — Effective but adds latency, cost, and
   an API dependency. Breaks the stdlib-only constraint for the core engine.

3. **Keyword lists per language** — Maintain curated keyword lists for high-risk
   terms (ignore, override, execute, pretend) in top languages. More manageable
   than full pattern translation.

4. **Unicode script analysis** — Detect when a skill mixes scripts in
   suspicious ways (e.g. Cyrillic homoglyphs in otherwise Latin text).

5. **Hybrid: keyword lists now, LLM-assisted scanning later** — Start with
   the most impactful languages, leave room for an optional LLM-assisted
   deep scan in a future plan.

## Requirements

### I18N1: Multilingual keyword patterns for PI-001 (critical)

Add translated patterns for "ignore previous instructions" and equivalent
phrases in the following high-priority languages (based on LLM training data
coverage and skill ecosystem representation):

| Language   | Priority | Rationale |
|------------|----------|-----------|
| Chinese    | High     | Significant skill ecosystem presence |
| Spanish    | High     | 2nd most common native language globally |
| Russian    | High     | Common in security research |
| Japanese   | Medium   | Active AI development community |
| Korean     | Medium   | Active AI development community |
| German     | Medium   | Active developer community |
| French     | Medium   | Significant developer population |
| Arabic     | Medium   | Growing AI adoption |
| Portuguese | Low      | Growing developer community |
| Hindi      | Low      | Large developer population |

For MVP, target the High and Medium priority languages (8 total).

### I18N2: Multilingual keyword patterns for PI-002 and PI-003

Extend the same approach to safety bypass (PI-002) and role manipulation
(PI-003) rules. Focus on the most distinctive phrases:
- PI-002: "disable safety", "bypass security", "without restrictions"
- PI-003: "you are now", "pretend to be", "act as if"

### I18N3: Separate TOML files per language family

Organize multilingual rules in separate TOML files to keep them maintainable:
```
rules/data/prompt_injection.toml          # English (existing)
rules/data/prompt_injection_cjk.toml      # Chinese, Japanese, Korean
rules/data/prompt_injection_european.toml  # Spanish, German, French
rules/data/prompt_injection_other.toml     # Russian, Arabic
```

Portuguese and Hindi (low priority) are deferred to a future iteration.
The 3 TOML files cover the 8 high+medium priority languages.

Each file follows the same `[rules.PI-XXX-xx]` format (e.g. `PI-001-zh` for
Chinese variant of PI-001).

### I18N4: Script-mixing detection

Add a new rule for detecting suspicious script mixing:
- Rule ID: `PI-007`
- Severity: `medium`
- Detects: Cyrillic characters in otherwise Latin text (homoglyph attacks),
  e.g. using Cyrillic `а` (U+0430) instead of Latin `a` (U+0061).
- This catches a class of attack orthogonal to language-specific keywords.

### I18N5: Exclude patterns for legitimate multilingual content

Multilingual rules must include exclude patterns for legitimate uses:
- Documentation that discusses prompt injection as a security topic.
- Skills that are themselves security scanners or prompt injection detectors.
- Negation patterns in each language (equivalent of "do not ignore").

### I18N6: Test coverage

- Positive tests: injection phrases in each supported language trigger detection.
- Negative tests: benign content in each language does not trigger.
- Mixed-language tests: English skill with Chinese injection phrase still caught.
- Homoglyph tests: Cyrillic-Latin mixing detected by PI-007.

## Files Affected

| File | Change |
|------|--------|
| `src/skill_scan/rules/data/prompt_injection_cjk.toml` | New: CJK injection patterns |
| `src/skill_scan/rules/data/prompt_injection_european.toml` | New: Spanish, German, French patterns |
| `src/skill_scan/rules/data/prompt_injection_other.toml` | New: Russian, Arabic patterns |
| `src/skill_scan/rules/data/prompt_injection.toml` | Add PI-007 (script mixing) |
| `tests/unit/test_rules_prompt_injection_detection.py` | Multilingual detection test cases |
| `tests/unit/test_rules_prompt_injection_evasion.py` | Multilingual evasion test cases |
| `tests/fixtures/` | Fixture files with multilingual content |

## Acceptance Criteria

- `忽略之前的指令` in a SKILL.md body triggers PI-001-zh (critical).
- `ignoriere vorherige Anweisungen` triggers PI-001-de (critical).
- Benign Chinese/Japanese/Korean text does not trigger false positives.
- Cyrillic homoglyph substitution in Latin text triggers PI-007.
- Rule loader discovers and loads all `prompt_injection_*.toml` files.
- Pattern count is documented (for tracking maintenance burden).

## Pattern Quality Approach

Native speaker review is not available for initial implementation. Instead,
use a multi-source validation strategy:

1. **Cross-model generation**: Ask multiple LLMs (Claude, GPT, Gemini)
   independently for translations of each attack phrase. High confidence
   when 3+ models agree on the same phrasing.
2. **Existing datasets**: Source patterns from open-source multilingual
   prompt injection benchmarks (e.g. Garak framework, HackAPrompt dataset,
   multilingual injection test suites) where available.
3. **Beta confidence tag**: Add a `confidence` metadata field to each rule
   in TOML. Multilingual rules are tagged `confidence = "beta"` to signal
   they haven't had native speaker review. English rules are `confidence =
   "stable"`. This metadata is informational (shown in verbose output) and
   does not affect severity or verdict.
4. **Community contribution path**: Document the pattern format and invite
   native speakers to submit corrections/additions once the scanner is
   public. Each TOML file should include a comment header with contribution
   instructions.

Beta-quality patterns are far better than zero coverage. A Chinese injection
attempt caught at `info` severity with a beta confidence tag is more useful
than the current behavior of total blindness.

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Translation accuracy | Cross-model validation + beta confidence tag + community path |
| Pattern explosion | Keep to high-confidence phrases; avoid full sentence matching |
| False positives in native-language skills | Exclude patterns for negation and educational contexts |
| Maintenance burden | Separate files per language family; document pattern sources |

## Out of Scope

- LLM-assisted semantic scanning (future enhancement).
- Real-time translation of skill content before scanning.
- Full coverage of all 7,000+ human languages — we target the top 10 by
  relevance to the AI developer ecosystem.
- Detecting injection in code comments (only prose/markdown for now).
