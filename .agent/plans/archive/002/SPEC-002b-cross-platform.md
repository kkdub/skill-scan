# SPEC-002b: Cross-Platform Compatibility

## Problem

The scanner was developed and tested on Unix-like systems. Running on Windows
surfaces encoding and path-handling issues:

1. **Encoding crash**: `click.echo()` fails with `UnicodeEncodeError` when
   outputting `U+2192` (right arrow) on Windows terminals using cp1252.
   (`cli.py:36`)

2. **Path separators**: Findings report backslash paths (`scripts\cgm.py:3229`)
   on Windows because `Path.relative_to()` returns OS-native separators. This
   creates inconsistent output across platforms and breaks any downstream
   tooling that expects forward slashes.

3. **Potential encoding issues in file reading**: `scanner.py` reads files as
   UTF-8 and gracefully handles `UnicodeDecodeError`, but the error path
   silently skips files. On Windows, files may be encoded in other code pages
   (e.g. cp1252, Shift-JIS) that are valid but not UTF-8.

## Requirements

### CP1: Safe Unicode output

All CLI output must be safe for any terminal encoding. Two approaches (choose
one during implementation):

- **Option A**: Replace non-ASCII characters with ASCII equivalents in
  formatter output (e.g. `->` instead of `U+2192`).
- **Option B**: Set `PYTHONIOENCODING=utf-8` at CLI entry or configure click's
  encoding handling.

Option A is preferred — it eliminates the class of problem entirely and keeps
output clean in pipes, redirects, and CI logs where encoding may be constrained.

### CP2: Consistent path separators in findings

Finding paths must always use forward slashes regardless of OS:
- `scripts/cgm.py:3229` (not `scripts\cgm.py:3229`)
- Applied at the point where `relative_to()` output enters a `Finding`.

### CP3: Encoding-aware file skip reporting

When a file is skipped due to encoding errors, emit an `info`-level finding
so the user knows it was skipped:
- Rule ID: `FS-001` (file safety)
- Category: `file-safety`
- Severity: `info`
- Include the file path and a note that the file was not UTF-8 decodable.

This makes the behavior observable rather than silently losing coverage.

### CP4: CI testing on Windows (DEFERRED)

Adding a Windows CI runner is an infrastructure decision deferred to a
follow-up. For PLAN-002, cross-platform correctness is verified via:
- Manual testing on Windows during development.
- Unit tests for path normalization that run on any OS.
- The encoding fix (CP1 Option A) is platform-independent and testable anywhere.

## Files Affected

| File | Change |
|------|--------|
| `src/skill_scan/formatters.py` | Replace `U+2192` with `->` (CP1 Option A) |
| `src/skill_scan/scanner.py` | Normalize path separators to `/` in findings (CP2); emit FS-001 on decode skip (CP3) |
| `tests/` | Add tests for path normalization and encoding edge cases |

## Acceptance Criteria

- `skill-scan scan <path>` runs without encoding errors on Windows cp1252 terminals.
- All finding file paths use forward slashes on every OS.
- Files skipped for encoding issues produce an observable `info` finding.
- All existing tests pass on both Unix and Windows.

## Out of Scope

- Supporting non-UTF-8 file scanning (we scan UTF-8 only, but report the skip).
- Terminal color/formatting (not yet implemented).
