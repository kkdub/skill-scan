# SPEC-002d: Output Deduplication and Grouping

## Problem

When a rule matches many times in a skill, the output is unusable. The
`niko91i_Skills-Vendure` scan produced 7,295 identical-looking findings — each
one a separate block with file, line, match, and recommendation. This is
~30,000 lines of output for a single rule.

The current formatter iterates `result.findings` and emits one block per
finding with no grouping, deduplication, or summarization.

## Current Behavior

```
[MEDIUM] PI-004: Hidden Unicode — ...
  File: references\Guides\core-concepts.md:12
  Match: "​"
  -> Strip or reject ...

[MEDIUM] PI-004: Hidden Unicode — ...
  File: references\Guides\core-concepts.md:15
  Match: "​"
  -> Strip or reject ...

... (7,293 more identical blocks)
```

## Requirements

### OD1: Group findings by rule ID

In text output, findings with the same `rule_id` must be grouped together
under a single heading rather than repeated individually.

### OD2: Collapse repeated findings within a group

When a rule produces multiple findings, display:
- The rule header (ID, severity, description) — once.
- A count: `N occurrences across M files`.
- A sample of up to 3 representative findings with file:line and match text.
- If there are more than 3, show `... and N more`.

Example output:
```
[MEDIUM] PI-004: Hidden Unicode — zero-width characters or directional overrides
  12 occurrences across 3 files
  references/Guides/core-concepts.md:12    "​"
  references/Guides/core-concepts.md:15    "​"
  references/Guides/core-concepts.md:21    "​"
  ... and 9 more
  -> Strip or reject content containing invisible Unicode control characters
```

### OD3: Single findings remain unchanged

When a rule produces exactly 1 finding, display it in the current format
(no grouping overhead).

### OD4: Configurable sample size

The number of sample findings shown (default: 3) should be a constant in the
formatter, not a config option. It can be promoted to config later if needed.

### OD5: Preserve full data in ScanResult

This is a **formatter-only** change. The `ScanResult.findings` tuple must
still contain every individual finding. Grouping/collapsing happens only at
the formatting layer. The Python API and future JSON output retain full detail.

## Files Affected

| File | Change |
|------|--------|
| `src/skill_scan/formatters.py` | Add grouping logic in `format_text()`; new `_format_finding_group()` |
| `tests/unit/test_formatters.py` | Tests for grouped output, single finding, edge cases |

## Acceptance Criteria

- A rule with 7,295 findings produces ~6 lines of output, not 30,000.
- A rule with 1 finding produces the same output as before.
- A rule with 2-3 findings shows all of them (within the sample window).
- A rule with 50 findings shows 3 samples + "... and 47 more".
- `ScanResult.findings` is unchanged — no data loss at the model layer.
- Grouped output still includes the recommendation (once per group).
- Summary section (counts, verdict, duration) is unchanged.

## Out of Scope

- JSON output grouping (JSON should remain flat for machine parsing).
- Interactive expand/collapse (terminal UI feature, not in scope).
- Configuring the sample size via CLI flags.
