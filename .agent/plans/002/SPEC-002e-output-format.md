# SPEC-002e: Output Format Redesign

## Problem

Beyond deduplication (SPEC-002d), the overall output structure needs
rethinking for usability. The current format is a flat list of findings
followed by a minimal summary. As the scanner adds more rule categories
(R4-R7), the output will grow and users need better structure to quickly
understand the security posture of a skill.

Key issues:
- No skill identification in the output header.
- No visual hierarchy between severity levels.
- Summary is minimal — just counts and verdict.
- No distinction between "actionable" findings and "informational" notes.
- The recommendation text is repeated per-finding (or per-group after 002d),
  even though it's the same for every finding of the same rule.

## Requirements

### OF1: Structured report header

Add a header section at the top of text output:
```
skill-scan report: <skill-name or directory name>
Scanned N files in M.NNs
```

If frontmatter was parsed successfully, use the skill `name` field. Otherwise
fall back to the directory basename.

### OF2: Severity-grouped sections

Organize findings by severity level, not by encounter order:
```
CRITICAL (0)
HIGH (0)
MEDIUM (3 findings, 2 rules)
  [PI-004] Hidden Unicode — ...
    ...
  [PI-005] HTML comment injection — ...
    ...
LOW (0)
INFO (1 finding, 1 rule)
  [SV-001] Schema validation — ...
    ...
```

- Only show sections that have findings (skip empty severity levels).
- Within each severity section, group by rule (per SPEC-002d).

### OF3: Verdict banner

End with a clear verdict block:
```
------------------
Verdict: FLAG
  3 medium, 1 info
  Scanned in 0.65s
```

The verdict line should be prominent and self-contained — a user skimming
output should be able to read just this block.

### OF4: Recommendation placement

Show the recommendation once per rule group, at the end of the group
(not per finding). This is a refinement of SPEC-002d's grouping.

### OF5: Quiet mode

Add `--quiet` / `-q` flag to `skill-scan scan`:
- Outputs only the verdict line and summary counts.
- Useful for CI pipelines that only need pass/fail.
- Example: `Verdict: FLAG (3 medium, 1 info)`

### OF6: Verbose mode

Add `--verbose` / `-v` flag to `skill-scan scan`:
- Shows all findings individually (no grouping/collapsing).
- Includes full matched text (up to 200 chars, current behavior).
- Useful for debugging specific findings.

### OF7: Default mode is the grouped/structured format

The default (no flags) uses OF1-OF4: header, severity sections, grouped
findings with samples, verdict banner.

## Files Affected

| File | Change |
|------|--------|
| `src/skill_scan/formatters.py` | Rewrite `format_text()` with severity sections, header, verdict banner |
| `src/skill_scan/cli.py` | Add `--quiet` and `--verbose` flags |
| `src/skill_scan/models.py` | Possibly add `skill_name: str | None` to `ScanResult` |
| `src/skill_scan/scanner.py` | Capture skill name (from frontmatter or directory) into `ScanResult` |
| `tests/unit/test_formatters.py` | Tests for all three output modes |
| `tests/integration/test_cli.py` | Tests for `--quiet` and `--verbose` flags |

## Acceptance Criteria

- Default output shows structured header, severity sections, grouped findings,
  verdict banner.
- `--quiet` outputs a single verdict summary line.
- `--verbose` outputs every finding individually (backwards-compatible format).
- Skill name appears in the header when available.
- Empty severity sections are omitted.
- Recommendations appear once per rule, not per finding.
- All existing CLI integration tests updated.

## Design Notes

- This spec builds on SPEC-002d (deduplication). Implement 002d first, then
  layer 002e on top.
- The formatter must remain a pure function: `format_text(result, mode)` where
  mode is an enum (`default`, `quiet`, `verbose`).
- ASCII-only output characters (per SPEC-002b).

## Out of Scope

- Color/ANSI formatting (future enhancement).
- JSON output restructuring (JSON stays flat for machine parsing).
- HTML report generation.
- Interactive terminal UI.
