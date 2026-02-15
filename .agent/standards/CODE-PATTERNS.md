# Code Patterns: Design Guidance for Python 3.13+

> **Purpose**: Situational design guidance agents consult *before* making architectural decisions.
> **Not rules** — enforceable constraints live in `code-rules.json`. This document answers
> "how should I structure this?" not "what must I check?"
>
> **Format**: Each pattern follows SITUATION → DECIDE → EXAMPLE → TRAP.
> Cross-references to `code-rules.json` rule IDs appear where relevant.

---

## 1. Separating Decisions from I/O

**SITUATION**: Function mixes conditional logic with side effects (HTTP, logging, filesystem).

**DECIDE**: Split into a pure decision function and an I/O orchestrator.

**Related rules**: ARCH-001, ARCH-003, ARCH-004

```python
# Pure decision — no I/O, trivially testable
def classify_finding(finding: Finding) -> Severity:
    if finding.matched_text and finding.rule_id.startswith("PI-"):
        return Severity.CRITICAL
    return Severity.LOW

# Orchestrator — coordinates I/O based on decision
def scan_file(path: Path, rules: list[Rule]) -> list[Finding]:
    content = path.read_text()
    return [f for rule in rules if (f := rule.check(content))]
```

**TRAP**: "The decision is only one line." It will grow. Extract early.

---

## 2. Injecting Time

**SITUATION**: Function needs current time (cache expiry, rate limit checks).

**DECIDE**: Accept time as a parameter. Never call `datetime.now()` inside business logic.

**Related rules**: ARCH-002

```python
def is_cache_stale(cached_at: datetime, now: datetime, ttl: timedelta) -> bool:
    return (now - cached_at) > ttl
```

**TRAP**: `now: datetime = datetime.now(UTC)` as default — evaluated once at definition time.

---

## 3. Returning Results Instead of Logging

**SITUATION**: Function performs work and you want to log what happened.

**DECIDE**: Return a result object. Let the caller handle logging.

**Related rules**: ARCH-003

```python
@dataclass(slots=True, frozen=True)
class ScanResult:
    findings: list[Finding]
    counts: dict[str, int]
    verdict: str
    duration: float

# Boundary layer logs the result
result = scan(skill_path)
logger.info("Scan complete", verdict=result.verdict, findings=len(result.findings))
```

---

## 4. Project Organization

This project uses **layered** organization:

```
src/skill_scan/
├── cli.py            # CLI entry points
├── config.py         # Configuration loading
├── models.py         # Data models (pure)
├── scanner.py        # Core scan engine
├── rules/            # Detection rule definitions
└── [future modules]
```

**Rules**:
- Models are pure — no I/O, no logging
- Scanner handles file reading and rule application
- CLI is the boundary layer (logging, user output)

---

## 5. Type System

- Use `X | None` not `Optional[X]` (TYPE-001)
- Import from `collections.abc` for `Callable`, `Sequence` (TYPE-002)
- Use `Self` for methods returning own type (TYPE-003)
- Type hints on all public functions (TYPE-007)

---

## Related Files

| File | Purpose |
|---|---|
| `.agents/standards/code-rules.json` | Enforceable rules |
| `.agents/standards/TEST-PATTERNS.md` | Test writing standards |
