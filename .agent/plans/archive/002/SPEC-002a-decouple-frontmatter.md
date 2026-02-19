# SPEC-002a: Decouple Frontmatter Validation from Security Scanning

## Problem

The scanner currently treats frontmatter validation (R0) as a hard gate: if
`parse_skill_frontmatter()` fails, the entire scan returns `Verdict.INVALID`
with zero security findings. This means 56% of real-world skills (19/34 in our
test corpus) get no security analysis at all.

Frontmatter validation and security scanning serve different purposes:
- **Frontmatter validation**: "Does this skill conform to the agent skills spec?"
- **Security scanning**: "Is this skill safe to install?"

A skill with missing frontmatter can still contain prompt injection or malicious
code. Blocking the scan on a schema issue creates a blind spot.

## Current Behavior

```
scanner.py:50-61
  if not cfg.skip_schema_validation:
      try:
          parse_skill_frontmatter(skill_dir)
      except SkillParseError as e:
          return ScanResult(verdict=INVALID, findings=(), ...)
```

The `skip_schema_validation` config flag exists but is not exposed via CLI.

## Requirements

### F1: Separate validation from scanning in the pipeline

The scan pipeline must run security rules regardless of frontmatter validation
outcome. Frontmatter issues become findings (not a hard stop).

- When frontmatter is invalid, emit a finding with a new rule category
  `schema-validation` (e.g. rule ID `SV-001`) at severity `info`.
- Continue to file collection and pattern scanning after the finding is emitted.
- `Verdict.INVALID` is removed from the enum. `Verdict` becomes a 3-value
  enum: `PASS`, `FLAG`, `BLOCK`. Schema issues alone do not determine verdict.

### F2: Standalone `validate` subcommand

Add `skill-scan validate <path>` as a separate CLI command:
- Runs only frontmatter parsing and validation.
- Reports detailed validation errors (missing fields, bad name format, etc.).
- Exit code 0 = valid, exit code 1 = invalid.
- Does NOT run security rules.

### F3: Deprecate `skip_schema_validation` config

With frontmatter no longer blocking the scan, `skip_schema_validation` is
unnecessary. Remove it from `ScanConfig`.

### F4: CLI flag `--strict-schema`

Add `--strict-schema` flag to `skill-scan scan`:
- When set, frontmatter validation failure raises the finding severity from
  `info` to `medium` (contributes to `flag` verdict).
- Default behavior (without flag): frontmatter issues are `info` only (do not
  affect verdict).

## Files Affected

| File | Change |
|------|--------|
| `src/skill_scan/scanner.py` | Remove hard-stop on parse failure; emit SV-001 finding instead |
| `src/skill_scan/config.py` | Remove `skip_schema_validation`; add `strict_schema: bool` |
| `src/skill_scan/cli.py` | Add `validate` subcommand; add `--strict-schema` flag to `scan` |
| `src/skill_scan/models.py` | Remove `Verdict.INVALID`; Verdict becomes 3-value enum (PASS/FLAG/BLOCK) |
| `src/skill_scan/formatters.py` | Update INVALID handling in text formatter |
| `tests/` | Update all tests that assert on INVALID verdict behavior |

## Acceptance Criteria

- A skill with no frontmatter still gets full security scanning and findings.
- `skill-scan validate <path>` reports schema issues without running rules.
- `skill-scan scan <path>` with invalid frontmatter returns security verdict
  (pass/flag/block), not `invalid`.
- `--strict-schema` elevates schema issues to affect verdict.
- Exit code 3 (INVALID) is no longer returned from `scan` subcommand.
- All existing tests updated and passing.

## Design Decisions

- **Verdict.INVALID is removed**, not repurposed. The `validate` subcommand
  uses simple exit codes (0/1) and does not need a verdict enum value. This
  keeps the verdict semantics clean: verdicts are security assessments, not
  schema assessments.
- The `_EXIT_CODES` dict in `cli.py` drops the INVALID entry. The `validate`
  subcommand manages its own exit codes independently.
- `ScanResult.error_message` field can be removed or repurposed for general
  warnings (since INVALID no longer exists as a verdict).

## Migration / Breaking Changes

This is a **breaking change** to the Python API and CLI contract:

- **Python API**: Code that checks `result.verdict == Verdict.INVALID` will
  break. Callers should check for `SV-001` findings in `result.findings`
  instead.
- **CLI exit codes**: Scripts that check for exit code 3 will no longer see
  it from `scan`. Use `skill-scan validate` for schema-only checks.
- **Acceptable**: This project is pre-1.0 with no external consumers yet.
  No deprecation period needed — update all internal tests in part b.

## Out of Scope

- "Assess and create frontmatter" workflow (future enhancement).
- Changes to the frontmatter validation rules themselves (name format, etc.).
