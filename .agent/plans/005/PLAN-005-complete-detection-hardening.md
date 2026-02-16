# PLAN-005 Complete Detection Hardening

## Overview

Quality-first hardening roadmap to close confirmed scanner blind spots, achieve platform-equal detection assurance across macOS/Windows/Linux, and extend scanning to MCP artifacts via a separate in-repo module.

## Objectives

- Eliminate high-confidence bypass classes before broadening detection surface.
- Preserve deterministic behavior and bounded runtime as coverage grows.
- Certify parity of detection assurance across Linux, Windows, and macOS.
- Add MCP scanning in the same repo, with a clean module boundary for gateway consumers.

## Workstream P0: Architectural Security Fixes (Blockers)

### 1) Add multi-line matching capability

- Files: `src/skill_scan/rules/engine.py`, `src/skill_scan/models.py`, `src/skill_scan/rules/loader.py`, `src/skill_scan/scanner.py`
- Introduce file-scope matching API (alongside line-scope) and map match offsets back to line numbers.
- Add `match_scope` metadata (`line` or `file`) with backward-compatible default behavior.

### 2) Decouple file-safety findings from content scanning

- Files: `src/skill_scan/scanner.py`, `src/skill_scan/config.py`, `src/skill_scan/file_checks.py`, `src/skill_scan/verdict.py`
- Emit FS findings and still content-scan when readable text exists.
- Unknown extension should no longer imply hard skip of behavioral scanning.
- Replace oversized hard-skip with bounded partial scanning plus explicit coverage metadata.
- Replace silent `OSError` drops with explicit findings.

### 3) Raise semantics for unscanned risk

- Files: `src/skill_scan/verdict.py`, `src/skill_scan/models.py`, `src/skill_scan/formatters.py`
- Add scan coverage fields (files/bytes scanned, degraded reasons).
- Apply verdict policy that upgrades severe scan degradation to at least FLAG.

### 4) Harden exclude-pattern behavior

- Files: `src/skill_scan/rules/engine.py`, `src/skill_scan/models.py`, `src/skill_scan/rules/loader.py`, `src/skill_scan/rules/data/*`
- Evaluate primary matches before exclusion logic.
- Add stricter exclusion mode metadata to prevent same-line piggyback suppression.

## Workstream P1: Coverage Expansion

### 5) Expand execution detection families

- Files: `src/skill_scan/rules/data/malicious_code.toml` (+ focused new files as needed)
- Add patterns for dynamic indirection (`__import__`, `getattr`, `importlib`, `compile+exec`), unsafe deserialization (`pickle`, unsafe `yaml.load`, `marshal`), and broader PowerShell cradle patterns.

### 6) Expand exfiltration detection families

- Files: `src/skill_scan/rules/data/data_exfiltration.toml`
- Add coverage for Python HTTP clients (`requests`, `httpx`, `urllib`), raw socket and DNS-like channels, and mail/websocket callback paths.

### 7) Add JS/TS and tool-instruction abuse coverage

- Files: new rule TOMLs in `src/skill_scan/rules/data/`
- Add JS/TS execution and command-launch signatures.
- Add tool/MCP abuse instruction signatures (dangerous paths, destructive chaining).

### 8) Improve obfuscation and Unicode robustness

- Files: `src/skill_scan/rules/data/prompt_injection.toml`, `src/skill_scan/scanner.py` (or dedicated normalization module)
- Add normalized matching pass (zero-width stripping, whitespace canonicalization).
- Expand confusable-script coverage.
- Add shorter encoded payload heuristics with FP controls.

## Workstream P2: Verification, Performance, and Release Quality

### 9) Build bypass regression corpus

- Files: `tests/unit`, `tests/integration`, fixtures
- Add positive/negative/evasion cases for multiline, obfuscation, exclusions, coverage degradation, and rule-family expansions.

### 10) Add coverage assertions and observability tests

- Validate explicit findings and verdict impact for unknown extensions, oversized files, decode failures, and read errors.

### 11) Performance and ReDoS safety gate

- Add stress tests for long lines/files and pathological regex patterns.
- Ensure bounded runtime with multiline and normalization logic enabled.

### 12) End-to-end release gate

- Require full quality and security suite pass.
- Document rule semantics, scan coverage reporting, and false-positive tradeoffs.

## Workstream P3: Platform-Equal Assurance (macOS, Windows, Linux)

### 13) OS matrix CI for assurance parity

- Files: `.github/workflows/ci.yml`
- Run quality, security, and test jobs on `ubuntu-latest`, `windows-latest`, and `macos-latest`.

### 14) Golden corpus cross-OS parity checks

- Files: `tests/*`, `.github/workflows/ci.yml`
- Create deterministic finding fingerprints and compare across OS runs.
- Enforce explicit acceptable diff policy (format/location-only deltas).

### 15) Encoding and newline parity certification

- Files: `tests/*` fixtures, `src/skill_scan/scanner.py`
- Add UTF-8/UTF-16/cp1252-like fixture matrix.
- Add LF/CRLF/CR parity tests.
- Fail CI on platform-induced detection drift beyond policy.

## Workstream P4: MCP Scanner Extension (Same Repo, Separate Module)

### 16) Add MCP scanner module boundary and API

- Files: new module under `src/skill_scan/mcp`, exports in `src/skill_scan/__init__.py`
- Provide standalone MCP scan entrypoint suitable for MCP gateway integration.
- Keep shared package/release pipeline in this repo.

### 17) Extend shared rule schema for artifact targeting

- Files: `src/skill_scan/models.py`, `src/skill_scan/rules/loader.py`, `src/skill_scan/rules/data/*`
- Add explicit targets (for example: `skill`, `mcp`, `both`).
- Reuse overlapping logic without rule drift or duplicate code paths.

### 18) Add MCP-specific rule families

- Files: new MCP-focused TOMLs under `src/skill_scan/rules/data/`
- Cover tool capability abuse, dangerous argument forms, transport/callback exfiltration, and MCP metadata prompt injection.

### 19) Cross-artifact correlation and unified verdicting

- Files: `src/skill_scan/scanner.py`, new correlation module under `src/skill_scan`, `src/skill_scan/verdict.py`
- Add combined scan mode (skill + MCP artifacts) and correlation findings for attack chains that emerge only in combination.

### 20) MCP consumer and gateway integration contract

- Files: integration tests and docs in repo plan/docs locations
- Define stable input/output/failure/versioning contract.
- Add compatibility tests for external gateway consumers.

### 21) MCP regression corpus and certification

- Files: fixtures in `tests/*`, CI in `.github/workflows/ci.yml`
- Add MCP positive/negative/evasion corpus and cross-OS parity checks.
- Include MCP suites in full quality gate.

## Acceptance Criteria

- Multi-line bypass classes are detected where rule intent exists.
- No silent file drops: all degraded scan paths generate explicit findings.
- Exclude piggyback suppression is blocked by engine semantics.
- Expanded execution/exfiltration/tool-use rule families have positive + negative + evasion tests.
- Scan coverage metrics are surfaced and can impact verdict policy.
- CI passes on Linux, Windows, and macOS.
- Golden corpus parity checks pass under defined diff policy.
- Encoding and line-ending parity tests pass.
- MCP scanner module is importable and usable independently by gateway consumers.
- Shared rules support explicit target scoping without duplicate logic drift.
- MCP-specific and cross-artifact correlation tests pass with deterministic unified verdicting.
- Full `make check` and full pre-commit pass before completion.

## Execution Flow

```mermaid
flowchart TD
    input[SkillAndMCPArtifacts] --> fs[FileSafetyChecks]
    fs --> cov[CoverageAccounting]
    cov --> scan[LineAndFileScopeMatching]
    scan --> norm[NormalizationAndConfusables]
    norm --> rules[SharedAndTargetedRulePacks]
    rules --> corr[CrossArtifactCorrelation]
    corr --> findings[FindingsAndEvidence]
    findings --> verdict[DeterministicVerdict]
```
