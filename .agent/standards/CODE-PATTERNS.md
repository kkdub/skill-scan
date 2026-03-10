# Code Patterns: Design Guidance for Python 3.13+

## Section 1: Generic Rules

### Antipatterns

| Rule ID | Severity | Rule |
|---------|----------|------|
| ANTI-001 | error | IF function has mutable default THEN use None and initialize inside |
| ANTI-003 | error | IF need shared state THEN use class attributes or dependency injection |
| ANTI-004 | warning | IF creating background task THEN store reference and handle completion |
| ANTI-005 | warning | IF checking type THEN use isinstance() |
| ANTI-006 | info | IF lambda has complex logic THEN convert to named function |
| ANTI-007 | warning | IF building string in loop THEN use ''.join() |
| ANTI-008 | warning | IF using home directory THEN use Path.home() |
| ANTI-009 | warning | IF parsing JSON THEN handle JSONDecodeError explicitly |
| ANTI-010 | warning | IF using semaphore THEN use context manager |

### Architecture

| Rule ID | Severity | Rule |
|---------|----------|------|
| ARCH-001 | error | IF function has decisions AND I/O THEN split into pure decision function and I/O orchestrator |
| ARCH-002 | error | IF function needs current time THEN accept time as parameter |
| ARCH-003 | error | IF function has business logic AND logging THEN return result object with metadata, log at boundary |
| ARCH-004 | error | IF function decides AND executes THEN split into classifier (returns decision) and executor (acts on decision) |
| ARCH-005 | error | IF writing business logic THEN keep it pure (no I/O); IF need I/O THEN do it in service/adapter layer |

### Async

| Rule ID | Severity | Rule |
|---------|----------|------|
| ASYNC-001 | error | IF tasks are dependent/transactional THEN TaskGroup; IF tasks are independent and partial results OK THEN gather(return_exceptions=True) |
| ASYNC-002 | error | IF need timeout on async operation THEN use asyncio.timeout context |
| ASYNC-003 | error | IF function has no await THEN remove async keyword |
| ASYNC-004 | error | IF calling async function THEN use await (or pass to TaskGroup/create_task) |
| ASYNC-005 | error | IF need delay in async THEN use await asyncio.sleep() |
| ASYNC-006 | error | IF file I/O in async function THEN use aiofiles |

### Control

| Rule ID | Severity | Rule |
|---------|----------|------|
| CONTROL-001 | error | IF 3+ conditionals for same variable THEN use match/case |

### Dataclasses

| Rule ID | Severity | Rule |
|---------|----------|------|
| DATA-001 | error | IF defining dataclass THEN add slots=True, frozen=True unless mutability needed |
| DATA-002 | error | IF dataclass field has mutable default THEN use field(default_factory=...) |

### Design

| Rule ID | Severity | Rule |
|---------|----------|------|
| DESIGN-001 | error | IF same code block appears in 2+ places THEN extract to shared helper |
| DESIGN-002 | error | IF solution seems complex THEN ask 'is there a simpler way?' |

### Errors

| Rule ID | Severity | Rule |
|---------|----------|------|
| ERROR-001 | error | IF catching exceptions THEN specify exception type |
| ERROR-002 | error | IF raising in except block THEN add from e |
| ERROR-003 | warning | IF catching broad exception THEN log and either re-raise or handle specifically |

### Fastapi

| Rule ID | Severity | Rule |
|---------|----------|------|
| FASTAPI-001 | error | IF using same dependency in multiple endpoints THEN create type alias |
| FASTAPI-002 | error | IF dependency returns service THEN use Protocol type |

### Files

| Rule ID | Severity | Rule |
|---------|----------|------|
| FILE-001 | error | IF doing path operations THEN use pathlib.Path |
| FILE-002 | error | IF opening file THEN use with context manager |

### Inheritance

| Rule ID | Severity | Rule |
|---------|----------|------|
| INHERIT-001 | error | IF method overrides parent/protocol THEN add @override decorator |
| INHERIT-002 | error | IF adding behavior via inheritance THEN consider protocol + composition instead |

### Pydantic

| Rule ID | Severity | Rule |
|---------|----------|------|
| PYDANTIC-001 | error | IF defining Pydantic model THEN add model_config = ConfigDict(extra='forbid') |
| PYDANTIC-002 | error | IF API model field THEN add Field with description and constraints |
| PYDANTIC-003 | error | IF validating across fields THEN use @model_validator |

### Runtime

| Rule ID | Severity | Rule |
|---------|----------|------|
| RUNTIME-001 | error | IF validating input THEN use explicit if/raise instead of assert |
| RUNTIME-002 | error | IF need shared state THEN use class attributes, closures, or dependency injection |

### Security

| Rule ID | Severity | Rule |
|---------|----------|------|
| SECURITY-001 | error | IF using subprocess THEN use shell=False with list of arguments |

### Shell

| Rule ID | Severity | Rule |
|---------|----------|------|
| SHELL-001 | error | IF printing error message in shell THEN redirect to stderr |
| SHELL-002 | error | IF writing shell script THEN add set -e at top |
| SHELL-003 | error | IF using variable in shell THEN wrap in double quotes |

### Size

| Rule ID | Severity | Rule |
|---------|----------|------|
| SIZE-001 | error | IF file > 500 lines THEN identify responsibilities and split into modules |
| SIZE-002 | error | IF function > 50 lines THEN extract logical sections to helper functions |

### Strings

| Rule ID | Severity | Rule |
|---------|----------|------|
| STRING-001 | error | IF formatting strings THEN use f-string |

### Structure

| Rule ID | Severity | Rule |
|---------|----------|------|
| STRUCTURE-001 | warning | IF file handles multiple unrelated concerns THEN split by responsibility into focused modules |
| STRUCTURE-002 | info | IF package has __init__.py THEN define __all__ listing public exports |
| STRUCTURE-003 | info | IF importing from project modules THEN use absolute import path |

### Types

| Rule ID | Severity | Rule |
|---------|----------|------|
| TYPE-001 | error | IF you see Optional[X] THEN replace with X | None |
| TYPE-002 | error | IF importing Callable/Mapping/Sequence from typing THEN use collections.abc |
| TYPE-003 | error | IF method returns own class instance THEN use Self |
| TYPE-004 | error | IF defining type alias THEN use type keyword |
| TYPE-005 | error | IF need unknown type THEN use object (or add # type: ignore comment) |
| TYPE-006 | error | IF function accepts collection THEN use Iterable/Sequence; IF returns THEN use list/dict/tuple |
| TYPE-007 | error | IF function/method is public (no _ prefix) THEN annotate all parameters and return type |

---

## Section 2: Project-Specific Patterns

## Separating Decisions from I/O

Split functions that mix conditional logic with side effects into a pure decision function and an I/O orchestrator.

```python
# Pure decision -- no I/O, trivially testable
def classify_finding(finding: Finding) -> Severity:
    if finding.matched_text and finding.rule_id.startswith("PI-"):
        return Severity.CRITICAL
    return Severity.LOW

# Orchestrator -- coordinates I/O based on decision
def scan_file(path: Path, rules: list[Rule]) -> list[Finding]:
    content = path.read_text()
    return [f for rule in rules if (f := rule.check(content))]
```

**Trap**: "The decision is only one line." It will grow. Extract early.

## Injecting Time

Accept time as a parameter; never call datetime.now() inside business logic.

```python
def is_cache_stale(cached_at: datetime, now: datetime, ttl: timedelta) -> bool:
    return (now - cached_at) > ttl
```

**Trap**: now: datetime = datetime.now(UTC) as default -- evaluated once at definition time.

## Returning Results Instead of Logging

Return a result object from functions that perform work; let the caller handle logging.

```python
@dataclass(slots=True, frozen=True)
class ScanResult:
    findings: list[Finding]
    verdict: str

result = scan(skill_path)
logger.info("Scan complete", verdict=result.verdict, findings=len(result.findings))
```

## Project Organization

Use layered organization with pure models, a core engine, and a boundary CLI.

```
src/skill_scan/
  cli.py        # CLI entry points (logging, user output)
  config.py     # Configuration loading
  models.py     # Data models (pure, no I/O)
  scanner.py    # Core scan engine
  rules/        # Detection rule definitions
```

## Type System

Use modern Python 3.13+ type syntax throughout.

```python
# Correct
def get_user(id: int) -> User | None: ...
from collections.abc import Callable, Sequence
type Predicate = Callable[[str], bool]

# Wrong
from typing import Optional, Callable  # TYPE-001, TYPE-002
```

## Prepare-Compute-Commit Pattern

Use private `_prepare_*` functions to validate inputs and build typed context dataclasses. The prepare function either returns a fully-populated context object or raises a domain exception -- it never returns an error string or a partial result.

```python
@dataclass(slots=True, frozen=True)
class _EditContext:
    file_path: str
    section: Section
    lines: list[str]

def _prepare_edit_context(
    file_path: str,
    section_id: str,
    ctx: Context | None,
    *,
    ensure_repo_set_func: Callable[..., None],
    get_text_content_cached_func: Callable[..., tuple[str, list[str]]],
) -> _EditContext:
    """Validate and build context. Raises on failure."""
    ensure_repo_set_func(ctx)            # raises RepositoryNotSetError
    ensure_markdown_file(file_path)      # raises NotMarkdownFileError
    content, lines = get_text_content_cached_func(file_path, ctx)
    sections = parse_sections(content)
    section = resolve_section_or_raise(sections, section_id)  # raises SectionNotFoundError
    return _EditContext(file_path=file_path, section=section, lines=lines)
```

**Rules**:
- `_prepare_*` NEVER returns error strings or `Context | str` unions.
- `_prepare_*` either returns a typed context dataclass or raises.
- Downstream `_compute_*` and `_commit_*` helpers can assume inputs are already valid.

## Exception-Based Error Flow

Domain exceptions are defined in their respective feature modules (for example, `src/skill_scan/_github_api.py` and `src/skill_scan/parser.py`). Guard functions (`ensure_*`) raise on failure and return `None` on success. There are no partial-result tuples or sentinel string returns.

```python
# CORRECT: guard raises or returns None
def ensure_markdown_file(file_path: str) -> None:
    if not file_path.endswith(".md"):
        raise NotMarkdownFileError(file_path)

# CORRECT: fetch returns clean value or raises
def get_content(file_path: str, ctx: Context | None, ...) -> tuple[str, list[str]]:
    raw = fetch_raw(file_path, ctx)          # raises InvalidTextEncodingError on bad bytes
    return raw, raw.splitlines(keepends=True)

# WRONG: triple-tuple with error sentinel
def get_content(...) -> tuple[str, list[str], str | None]: ...  # never do this

# WRONG: str | None guard return
def ensure_markdown_file(file_path: str) -> str | None: ...     # never do this

# WRONG: for-early-error chain
for early_err in [validate_a(), validate_b()]:
    if early_err:
        return error_response(early_err)    # never do this
```

**Rules**:
- No `(value, lines, error)` triple-tuple returns -- functions return clean values or raise.
- No `str | None` guard returns -- guards raise or return `None`.
- No `for early_err in [...]` chains.
- Domain exceptions are defined in their respective feature modules.

## Tool Boundary Exception Catch

The outermost `*_impl` function for each MCP tool is the single exception boundary. It wraps the prepare-compute-commit chain in a `try/except Exception` block and converts any exception to a structured JSON error response via `exception_to_error_response()`.

```python
def delete_section_impl(
    file_path: str,
    section_id: str,
    ctx: Context | None,
    *,
    ensure_repo_set_func: Callable[..., None],
    get_text_content_cached_func: Callable[..., tuple[str, list[str]]],
    write_func: Callable[..., str],
) -> str:
    try:
        context = _prepare_delete_context(
            file_path, section_id, ctx,
            ensure_repo_set_func=ensure_repo_set_func,
            get_text_content_cached_func=get_text_content_cached_func,
        )                                    # may raise RepositoryNotSetError, SectionNotFoundError, etc.
        result = _compute_deletion(context)  # pure logic, may raise
        return _commit_and_respond(context, result, write_func=write_func)
    except Exception as e:
        return exception_to_error_response(e)
```

Full exception flow:
1. Guard inside `_prepare_*` raises (e.g. `NotMarkdownFileError("report.txt")`)
2. Exception propagates up through `_compute_*` / `_commit_*` without being caught
3. Boundary `except Exception` catches it
4. `exception_to_error_response(e)` maps it to `{"success": false, "code": "not_markdown_file", "error": "..."}`

**Rules**:
- Exactly ONE `try/except Exception` per tool impl, at the outermost level.
- Never catch exceptions inside `_prepare_*`, `_compute_*`, or `_commit_*` helpers.
- Never return error strings from helpers -- raise instead.

## Filename Sanitization (SEC-001)

Sanitize any user-controlled string used as a filename by stripping everything except safe characters, then verify the final path stays inside the target directory as defense-in-depth.

```python
def _sanitize_filename(name: str) -> str:
    """Strip all chars except [a-zA-Z0-9_-]. Returns '_' if result is empty."""
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    return sanitized if sanitized else "_"

def _verify_path_containment(file_path: Path, save_path: Path) -> None:
    """Raise ValueError if file_path escapes save_path (defense-in-depth)."""
    if not file_path.resolve().is_relative_to(save_path.resolve()):
        raise ValueError(f"Path traversal blocked: {file_path} is not inside {save_path}")
```

> Trap: replacing only `.` with `_` is insufficient — path separators (`/`, `\`) and null bytes also bypass directory containment.

## AST Analysis for Python Files

For `.py` files, `content_scanner.py` runs AST analysis after regex scanning and deduplicates by `(rule_id, line)`. The public entry point is `analyze_python(content, file_path) -> list[Finding]` in `ast_analyzer.py`. String resolution helpers live in `_ast_helpers.py`.

```python
# content_scanner.py — integration point
regex_findings = match_content(content, relative_path, applicable)
if relative_path.endswith(".py"):
    ast_findings = analyze_python(content, relative_path)
    return _deduplicate(regex_findings, ast_findings)
return regex_findings
```

> Trap: `ast_analyzer.py` is at the 250-line limit. Any new detector must be split into a sibling module first (follow the Facade Re-export Pattern).

## Multi-Pass Scanning in match_content()

`match_content()` in `engine.py` applies four sequential passes. Each pass extends the findings list without interfering with earlier passes. New passes follow the same helper-function pattern.

```python
def match_content(content, file_path, rules, *, _depth=0):
    # Pass 1: line rules (original text)
    # Pass 2: line rules (normalized text — deduped against pass 1)
    # Pass 3: file-scope rules (original + normalized)
    # Pass 4: decoded-content rules (base64/hex payloads, recursive up to MAX_DECODE_DEPTH)
    ...
    if _depth < MAX_DECODE_DEPTH:
        findings.extend(_decoded_content_findings(content, file_path, rules, _depth))
    return findings
```

> Trap: decoded findings keep the original file path and line number (where the encoded string was found), not a line number inside the decoded text. Prefix the description with `[decoded]` so users know the match came from a decoded payload.

## Output Formatter Pattern

Output formatters are pure functions that take a `ScanResult` and return a string. No I/O, no side effects. New formats get their own module, are registered in `cli.py`'s format `Choice`, and exported via `__init__.__all__`.

```python
# sarif_formatter.py (or json_formatter.py)
def format_sarif(result: ScanResult) -> str:
    """Format a ScanResult as a SARIF 2.1.0 JSON string."""
    data = {...}
    return json.dumps(data, indent=2)
```

> Trap: adding I/O or side effects inside a formatter breaks testability and violates ARCH-001.

## Inline noqa Suppression

`suppression.py` provides two pure functions for inline finding suppression. `parse_noqa()` extracts rule IDs from a `# noqa: RULE-ID` comment on a single line; `filter_suppressed()` filters a findings list against the noqa directives of their source lines. Both are called inside `_scan_file()` after `_apply_rules()`, which means suppression works identically in sequential and concurrent paths.

```python
from skill_scan.suppression import filter_suppressed, parse_noqa

# parse a single line
ids = parse_noqa("x = eval(s)  # noqa: EXEC-002")  # frozenset({'EXEC-002'})
ids = parse_noqa("x = eval(s)  # noqa")             # frozenset() — bare noqa rejected

# filter a findings list
remaining, suppressed_count = filter_suppressed(findings, content.splitlines())
```

> Trap: bare `# noqa` (no rule IDs) returns an empty frozenset and suppresses nothing — explicit rule IDs are required.

## Concurrent File Scanning

`scan_all_files()` in `content_scanner.py` dispatches to `_scan_concurrent()` when `len(files) >= MIN_FILES_FOR_CONCURRENCY` (8) and falls back to `_scan_sequential()` on `OSError` or `RuntimeError`. The worker count is resolved by `_resolve_workers()`, which caps at 8 regardless of the `max_workers` config value.

```python
# content_scanner.py — dispatch logic
if len(files) >= MIN_FILES_FOR_CONCURRENCY:
    try:
        return _scan_concurrent(files, skill_dir, rules, max_file_size, max_workers)
    except (OSError, RuntimeError):
        pass  # fall back to sequential
return _scan_sequential(files, skill_dir, rules, max_file_size)
```

> Trap: `ProcessPoolExecutor` requires all arguments to `_scan_file()` to be picklable. `Finding`, `Rule`, and `ScanResult` are frozen dataclasses with `slots=True`, which satisfies this constraint. Do not add unpicklable types (locks, file handles) to the per-file scan arguments.

## Facade Re-export Pattern

When splitting a large module into sibling files, keep the original file as a facade: it retains the orchestrator/entry-point functions and types, then re-exports all names from sibling files at the BOTTOM. This preserves every existing import path and mock.patch target.

```python
# original_module.py  (facade)

# ... local definitions stay here (types, orchestrator functions) ...

# re-exports at BOTTOM -- backward-compat for all consumers
from src.package.original_module_helpers import (  # noqa: E402, F401
    _helper_a,
    _helper_b,
    PublicHelper,
)
```

**Rules**:
- Re-exports go at the BOTTOM of the facade, after all local definitions (prevents circular imports).
- Re-export ALL names (public and private) so every existing consumer import path continues to work.
- Sibling files import types/constants from the facade; the facade imports implementations from siblings (one-way in each direction, resolved by bottom-of-file placement).
- Use lazy imports inside function bodies when a sibling needs something from the facade that is not yet defined at import time (breaks the circular dependency without a package conversion).
