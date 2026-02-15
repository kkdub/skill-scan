# skill-scan: Security Scanner for Agent Skills

## Overview

A pip-installable Python library + CLI for scanning agent skills for security
issues before installation. Uses `skills-ref` (Anthropic's official reference
library) for spec compliance, adds security scanning on top.

Informed by:
- [Snyk ToxicSkills audit](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) — 36.82% of 3,984 skills have security flaws
- [Cisco AI Defense Skill Scanner](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) — 26% of 31,000 skills have vulnerabilities
- [Agent Skills Specification](https://agentskills.io/specification.md)
- [skills-ref reference library](https://github.com/agentskills/agentskills/tree/main/skills-ref)
- [arXiv: Prompt Injection Attacks on Agentic Coding Assistants](https://arxiv.org/html/2601.17548v1)
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Prompt Security: Top 10 MCP Security Risks](https://www.prompt.security/blog/top-10-mcp-security-risks)

## Stack

- **Python 3.11+**
- **`skills-ref`** — official Anthropic reference library for schema validation (Apache-2.0)
- **`click`** — CLI framework
- **`httpx`** — optional extra, for `--repo` remote scanning
- **`strictyaml`** — transitive via `skills-ref`
- **Core scanner engine: stdlib only** (`re`, `pathlib`, `json`, `tomllib`)
- **Dev:** `pytest`, `ruff`, `mypy`
- **Build:** `hatchling` (matches `skills-ref`)
- **Max 250 lines per source file**

---

## Requirements

### R0: Schema validation (via skills-ref)

Call `skills_ref.validate()` as the first gate before any security scanning.

- SKILL.md must exist
- Valid YAML front matter
- `name` required: 1-64 chars, lowercase alphanumeric + hyphens, no leading/trailing/consecutive hyphens, must match parent directory name
- `description` required: 1-1024 chars, non-empty
- Optional fields validated if present: `license`, `compatibility` (1-500 chars), `metadata` (string-to-string map), `allowed-tools`
- All text files must be valid UTF-8
- No unexpected top-level executables

**Verdict:** Schema failure = `invalid` — distinct from security verdicts. Scan stops here.

### R1: Python API

- `from skill_scan import scan` — scan a local directory
- Returns a structured result object:
  - `findings`: list of Finding objects
  - `counts`: dict of severity -> count
  - `verdict`: one of `pass`, `flag`, `block`, `invalid`
  - `duration`: scan time
- Each Finding:
  - `rule_id`: str (e.g. "PI-001")
  - `severity`: critical | high | medium | low | info
  - `category`: str (e.g. "prompt-injection")
  - `file`: str (relative path)
  - `line`: int | None
  - `matched_text`: str (truncated to 200 chars)
  - `description`: str
  - `recommendation`: str

### R2: CLI

- `skill-scan scan <path>` — scan a local skill directory or single file
- `skill-scan scan --repo <owner/repo> [--skill-path <path>]` — fetch from GitHub without cloning
- Exit codes:
  - 0 = pass (clean)
  - 1 = flag (warnings only, no critical/high)
  - 2 = block (critical or high findings)
  - 3 = invalid (schema failure)
- `--format text|json` — output format (default: text)
- `--fail-on <severity>` — override exit code threshold for CI
- `--config <path>` — custom rules/suppressions via TOML

### R3: Prompt injection detection

| Rule   | Severity | Description |
|--------|----------|-------------|
| PI-001 | critical | Direct override: "ignore previous instructions", "override system prompt", "forget your rules" |
| PI-002 | high     | Safety bypass: "skip safety checks", "disable content filter", "without restrictions" |
| PI-003 | high     | Role manipulation: "you are now", "act as if", "pretend to be" |
| PI-004 | medium   | Hidden Unicode: zero-width spaces/joiners, directional overrides, invisible characters between letters |
| PI-005 | medium   | HTML comment injection: `<!-- instructions hidden from rendered view -->` |
| PI-006 | medium   | Steganographic encoding: instructions disguised as formatting or metadata |

### R4: Malicious code detection

| Rule     | Severity | Description |
|----------|----------|-------------|
| EXEC-001 | critical | Remote code execution: `curl\|sh`, `wget\|bash`, `iex(Invoke-WebRequest...)`, piped downloads with interleaved flags |
| EXEC-002 | critical | Dynamic execution: `eval()`, `exec()`, `os.system()`, `subprocess` with `shell=True` |
| EXEC-003 | high     | Obfuscated payloads: base64 decode piped to shell, hex-encoded strings, encoded PowerShell |
| EXEC-004 | high     | Persistence mechanisms: crontab, LaunchAgents, systemd units, shell profile writes, startup dirs |
| EXEC-005 | high     | Binary download instructions: `.exe`, `.dmg`, `.pkg`, password-protected ZIPs |

### R5: Data exfiltration detection

| Rule      | Severity | Description |
|-----------|----------|-------------|
| EXFIL-001 | critical | Silent outbound requests: `curl -s` with POST data, hidden network calls |
| EXFIL-002 | high     | Sensitive path access: `~/.ssh`, `~/.aws`, `~/.gnupg`, `.env`, `/etc/shadow`, browser credential stores |
| EXFIL-003 | high     | Webhook/C2 patterns: callback URLs, Discord/Slack webhooks, phone-home patterns |
| EXFIL-004 | high     | Environment harvesting: `os.environ`, `printenv`, `process.env` bulk access |

### R6: Credential exposure detection

| Rule     | Severity | Description |
|----------|----------|-------------|
| CRED-001 | critical | Hardcoded secrets: AWS keys (`AKIA...`), GitHub tokens (`ghp_`), OpenAI keys (`sk-`), Slack tokens (`xox`), Google keys (`AIza`), private key blocks |
| CRED-002 | high     | Credentials in LLM context: instructions to pass tokens through conversation |
| CRED-003 | high     | Plaintext password patterns: `password=`, `secret=` with literal values |

### R7: Supply chain risk detection

| Rule   | Severity | Description |
|--------|----------|-------------|
| SC-001 | medium   | Remote instruction fetching: SKILL.md or config loaded from external URLs (content can change post-review) |
| SC-002 | medium   | Unpinned dependencies: `pip install <pkg>` without version pins |
| SC-003 | medium   | Broad filesystem access: path traversal (`../`), absolute paths, system dir access |
| SC-004 | high     | Social engineering prerequisites: "run this setup command", fake error messages with terminal commands (ClickFix pattern) |

### R8: File safety checks

| Check | Behavior |
|-------|----------|
| Binary detection | Block: `.exe`, `.so`, `.dll`, `.wasm`, `.pyc`, compiled binaries |
| Extension allowlist | Allow: `.md`, `.txt`, `.py`, `.sh`, `.yaml`, `.json`, `.toml`, `.jinja2`. Flag unknown extensions |
| Symlink detection | Block: symlinks pointing outside the skill directory |
| File size limit | Flag: >500KB per file (configurable) |
| Total size limit | Flag: >5MB total (configurable) |
| File count limit | Flag: >100 files (configurable) |

### R9: Structured reporting

- **Text mode:** human-readable terminal output with severity indicators
- **JSON mode:** machine-parseable for CI/CD and tooling integration
- **Summary:** counts by severity, overall verdict, scan duration
- **Deterministic:** same input always produces same findings (no randomness, no timestamps in findings)

### R10: Configurable rules

- Default ruleset covers R3-R7 out of the box
- Custom rules via TOML config: regex pattern + severity + category
- Rule suppression by ID for known false positives
- Config loadable via file path or Python API kwargs

---

## Testing Requirements

### Coverage principle

Every detection rule has at least one positive ("should catch") and one negative
("should not catch") test case.

### Evasion tests (false negatives)

These test that the scanner catches attempts to dodge detection:

- Unicode variants of instructions ("ignore" with zero-width chars between letters)
- Mixed case, extra whitespace, line breaks mid-pattern
- Base64-encoded payloads with varying padding and line wrapping
- `curl | sh` with flags interspersed (`curl -sL foo | bash -`)
- Credential patterns at unusual indentation or inside code fences
- HTML comments split across lines
- Nested obfuscation (base64 inside a hex-encoded string)

### Legitimacy tests (false positives)

These test that the scanner does NOT flag safe content:

- A skill that *describes* prompt injection as a warning ("do not ignore previous instructions")
- Documentation that *mentions* `~/.ssh` in a "don't do this" context
- A skill that legitimately uses `subprocess` for safe, non-shell operations
- Code examples showing `eval()` as an anti-pattern
- URLs in attribution/credits that aren't exfiltration endpoints
- Base64 strings that are just embedded images or test fixtures

### Boundary tests

- Empty SKILL.md (valid front matter, no body)
- Skill directory with no files other than SKILL.md
- Binary file mixed in with text files
- Extremely long single-line files (>100KB single line)
- Files with mixed/broken encoding (UTF-8 BOM, Latin-1, raw bytes)
- Symlink loops
- Filenames with special characters, spaces, or Unicode
- Deeply nested directory structures
- Skill directory that is itself a symlink

---

## Architecture Notes

### Scan pipeline

```
Input (path or repo URL)
  |
  v
R0: Schema validation (skills-ref)
  |-- invalid -> verdict: invalid, stop
  |
  v
R8: File safety checks
  |-- binary/symlink -> add findings, continue
  |
  v
R3-R7: Pattern scanning (all text files)
  |-- regex engine over file contents
  |-- line-level findings with context
  |
  v
R9: Report assembly
  |-- aggregate findings
  |-- compute verdict (worst severity)
  |-- format output (text or JSON)
```

### Verdict logic

- `invalid`: schema validation failed (R0)
- `block`: any critical or high finding
- `flag`: medium or low findings only
- `pass`: no findings (or info-only)

`--fail-on` overrides the exit code threshold but does not change the verdict
in the report.

### Integration with Scout (skill-bank)

Scout adds `skill-scan` as a dependency. Part G (download/install) calls
`skill_scan.scan()` before writing to disk. A `block` verdict prevents
installation. A `flag` verdict warns but allows installation with confirmation.
