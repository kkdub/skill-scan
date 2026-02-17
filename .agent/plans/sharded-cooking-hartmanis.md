# Refactor file_collector.py: Separate I/O from Decisions (ARCH-001)

## Context

`file_collector.py` violates ARCH-001 by mixing filesystem I/O (`rglob`, `is_symlink`, `stat`, `resolve`, `is_file`) with classification decisions (binary check, extension check, size check, skip-content logic). This makes the decision logic hard to unit-test without a real filesystem.

The project already established the pattern: `file_checks.py` holds pure per-file check functions. But the *orchestration* of those checks — deciding which to call, aggregating results, determining what to collect — is still tangled with I/O in `file_collector.py`.

**Goal**: Split into two focused modules so the classification logic is pure and trivially testable.

## Design

### New dataclass: `FileEntry` (in `models.py`)

```python
@dataclass(slots=True, frozen=True)
class FileEntry:
    """Filesystem metadata for a single entry in a skill directory."""
    path: Path
    relative_path: str
    suffix: str
    size: int                    # 0 for external symlinks
    is_external_symlink: bool    # symlink resolving outside skill root
    resolved_path: Path          # fully resolved path (for symlink reporting)
```

`models.py` grows from 76 → ~88 lines.

### Rewritten `file_collector.py` — I/O only (~55 lines)

Exports `walk_skill_dir(skill_dir: Path) -> tuple[list[FileEntry], Path]`.

- Walks `skill_dir.rglob("*")`
- For each path: calls `is_symlink()`, `resolve()`, `is_file()`, `stat()`
- Builds `FileEntry` with gathered metadata
- Filters out non-files, stat failures, internal symlinks to directories
- Returns `(entries, resolved_root)` — no classification, no findings

The `resolved_root` is returned alongside entries because the classifier needs it for the symlink-outside-root check.

### New `file_classifier.py` — pure decisions (~70 lines)

Exports `classify_entries(entries, resolved_root, config) -> tuple[list[Path], list[Finding]]`.

- Iterates `FileEntry` list
- Calls existing `file_checks.py` functions with entry metadata
- Owns `_SKIP_CONTENT_RULES` constant (decides what prevents content scanning)
- Runs aggregate checks (`check_total_size`, `check_file_count`)
- Returns `(collected_files, fs_findings)` — same signature as old `collect_files`

Internal helper `_classify_entry(entry, resolved_root, config) -> Finding | None`.

### Updated `scanner.py` — two-step call

```python
# Before:
files, fs_findings = collect_files(skill_dir, cfg)

# After:
from skill_scan.file_collector import walk_skill_dir
from skill_scan.file_classifier import classify_entries

entries, resolved_root = walk_skill_dir(skill_dir)
files, fs_findings = classify_entries(entries, resolved_root, cfg)
```

`scanner.py` stays at ~107 lines (+1 import line, +1 code line).

## Behavior preservation — symlink edge cases

Current `_check_entry` has nuanced symlink handling that must be preserved:

| Entry type | Walker behavior | Classifier behavior |
|---|---|---|
| External symlink (file/dir/broken) | Yields `FileEntry(size=0, is_external_symlink=True)` | Returns FS-004 finding, not collected |
| Internal symlink → file | Yields `FileEntry` with real size | Normal binary/ext/size checks |
| Internal symlink → directory | Filtered out (`is_file()` returns False) | Never sees it |
| Regular directory | Filtered out | Never sees it |
| stat() failure | Filtered out | Never sees it |

External symlinks count toward `file_count` and add 0 to `total_size` (matches current behavior).

## Files to modify

| File | Action | Lines before → after |
|---|---|---|
| `src/skill_scan/models.py` | Add `FileEntry` dataclass + `Path` import | 76 → ~88 |
| `src/skill_scan/file_collector.py` | Rewrite: I/O walker only | 106 → ~55 |
| `src/skill_scan/file_classifier.py` | **New**: pure classification | — → ~70 |
| `src/skill_scan/scanner.py` | Update imports + call site | 106 → ~107 |

All within 250-line limit.

## Verification

1. `make check` — all existing tests pass (file_collector is tested indirectly through `test_scanner_file_safety.py` and `test_scanner.py`)
2. Manually verify line counts stay within budget
3. Confirm no new `__init__.py` exports needed (both modules are internal)
