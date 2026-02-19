# skill-scan

Security scanner for agent skills — detects prompt injection, malicious code, and data exfiltration before installation.

## Features

- **73 detection rules** across 8 categories: prompt injection, malicious code, data exfiltration, credential exposure, supply chain, tool abuse, file safety, and schema validation
- **Multilingual prompt injection detection** — covers English, Arabic, Chinese, French, German, Japanese, Korean, Russian, and Spanish
- **Local and remote scanning** — scan a directory on disk or fetch from GitHub
- **Multiple output formats** — human-readable text or machine-readable JSON
- **CI-friendly** — `--fail-on` flag exits with code 2 when findings exceed a severity threshold
- **Zero runtime dependencies** beyond `click` — core engine uses stdlib only

## Installation

Requires Python 3.13+.

```bash
# Install with uv
uv pip install -e .

# Include remote GitHub scanning support
uv pip install -e ".[remote]"
```

## Usage

### Scan a local skill directory

```bash
skill-scan scan path/to/skill/
```

```
skill-scan report: my-skill
Scanned 1 files (136 bytes) in 0.04s

No security issues found.

------------------
Verdict: PASS
  Scanned in 0.04s
```

### Scan a GitHub repository

```bash
skill-scan scan --repo owner/repo
skill-scan scan --repo owner/repo@branch --skill-path skills/my-skill
```

### Output options

```bash
# JSON output (for CI pipelines or programmatic use)
skill-scan scan path/to/skill/ --format json

# Quiet mode (verdict only)
skill-scan scan path/to/skill/ --quiet

# Verbose mode (show all individual findings)
skill-scan scan path/to/skill/ --verbose

# Fail if any finding at or above a severity threshold
skill-scan scan path/to/skill/ --fail-on high
```

### Validate skill frontmatter

```bash
skill-scan validate path/to/SKILL.md
```

## Detection categories

| Category | Rules | Example threats |
|----------|-------|-----------------|
| Prompt Injection | PI-001 .. PI-009 | Instruction override, safety bypass, role manipulation, homoglyph attacks |
| Malicious Code | EXEC-001 .. EXEC-010, JSEXEC-001 .. JSEXEC-003 | Remote code execution, eval/exec, obfuscated payloads, unsafe deserialization |
| Data Exfiltration | EXFIL-001 .. EXFIL-007 | Silent outbound requests, credential harvesting, webhook/C2 callbacks |
| Credential Exposure | CRED-001 .. CRED-003 | Hardcoded API keys, plaintext passwords, secrets in LLM context |
| Supply Chain | SC-001 .. SC-004 | Remote config fetching, unpinned dependencies, ClickFix social engineering |
| Tool Abuse | TOOL-001 .. TOOL-003 | Destructive file ops, privilege escalation, dangerous command chaining |
| File Safety | FS-001 .. FS-008 | Binary files, symlink escapes, size limits, encoding issues |
| Schema Validation | SV-001 | Invalid SKILL.md frontmatter |

See [RULES.md](RULES.md) for the full catalog.

## Configuration

Pass a TOML config file to customize behavior:

```bash
skill-scan scan path/to/skill/ --config scan.toml
```

Custom rules can be authored using the [rule template](src/skill_scan/rules/template.toml).

## Python API

```python
from skill_scan import scan, Severity

result = scan("path/to/skill/")
print(result.verdict)  # Verdict.PASS or Verdict.BLOCK

for finding in result.findings:
    print(f"[{finding.severity.name}] {finding.rule_id}: {finding.description}")
```

## Development

```bash
# Install dev dependencies
make install

# Run all quality checks (ruff, mypy, bandit, pytest, custom linters)
make check
```

## License
