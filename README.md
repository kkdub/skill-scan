# skill-scan

Security scanner for agent skills — detects prompt injection, malicious code, and data exfiltration before installation.

## Features

- **77 detection rules** across 9 categories: prompt injection, malicious code, data exfiltration, credential exposure, supply chain, tool abuse, file safety, schema validation, and obfuscation
- **Multilingual prompt injection detection** — covers English, Arabic, Chinese, French, German, Japanese, Korean, Russian, and Spanish
- **Local and remote scanning** — scan a directory on disk or fetch from GitHub
- **Multiple output formats** — human-readable text, machine-readable JSON, or SARIF v2.1.0 for GitHub Code Scanning
- **CI-friendly** — `--fail-on` flag exits with code 2 when findings exceed a severity threshold
- **Encoded payload detection** — base64, hex, URL-encoded, and unicode-escape strings are decoded and recursively scanned, catching obfuscated injections that regex-only scanning misses
- **AST-based Python analysis** — `.py` files are parsed with Python's `ast` module to catch evasion techniques that regex cannot detect (string concatenation building `eval`, `chr()`-based construction, `getattr` with dynamic names, unsafe deserialization, ROT13 codec usage, and string-splitting evasion where dangerous names or encoded payloads are assembled across multiple variables via concatenation, f-strings with `!s`/`!r` conversions, `join` with lists/generators/`map(chr)`/`map(str)`, `str.format()`, `%`-formatting with mixed specifiers, dict subscript access, and string multiplication)
- **Concurrent scanning** — large skill directories (8+ files) are scanned in parallel using `ProcessPoolExecutor`, with automatic fallback to sequential scanning
- **Inline suppression** — add `# noqa: RULE-ID` to any line to suppress a specific finding; bare `# noqa` is rejected (security scanner requires explicit rule IDs); suppressed counts are reported for auditability
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

# SARIF output (for GitHub Code Scanning / GitLab SAST)
skill-scan scan path/to/skill/ --format sarif

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

## GitHub Action

Add skill-scan to any GitHub Actions workflow:

```yaml
- uses: actions/checkout@v4   # required for path mode
- uses: kkdub/skill-scan@main
  with:
    path: ./skills/my-skill   # local path (default: .)
    fail-on: high             # exit code 2 if high or critical findings
    format: sarif             # text | json | sarif
```

> **Tip:** Pin to a release tag (e.g., `@v1.0.0`) instead of `@main` for reproducible builds.

For remote repo scanning (no checkout needed):

```yaml
- uses: kkdub/skill-scan@main
  with:
    repo: owner/repo@main
    fail-on: high
```

When `format: sarif`, the action writes `skill-scan-results.sarif` and automatically uploads it to GitHub Code Scanning via `github/codeql-action/upload-sarif`.

**Inputs**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Local skill directory to scan |
| `repo` | — | Remote GitHub repo (`owner/repo` or `owner/repo@ref`) |
| `fail-on` | — | Severity threshold for non-zero exit (`critical`, `high`, `medium`, `low`, `info`) |
| `format` | `text` | Output format: `text`, `json`, or `sarif` |
| `config` | — | Path to a skill-scan TOML config file |

## Pre-commit Hook

Add skill-scan as a pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/kkdub/skill-scan
    rev: v1.0.0
    hooks:
      - id: skill-scan
        args: ['./skills']   # path to your skill directory
```

## Docker

Run skill-scan in an isolated container — useful when scanning potentially untrusted skill content.

```bash
# Build the image
docker build -t skill-scan .

# Scan a local directory
docker run --rm -v ./my-skill:/scan:ro skill-scan scan /scan

# All CLI flags work via ENTRYPOINT passthrough
docker run --rm -v ./my-skill:/scan:ro skill-scan scan /scan --format json --fail-on high

# Remote scanning works without a volume mount
docker run --rm skill-scan scan --repo owner/repo
```

The container runs as non-root user `scanner`. The scan target is mounted read-only at `/scan` (the container's working directory). By default, the container can only access host files under this mounted directory unless you add additional volume mounts.

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
| Obfuscation | OBFS-001 .. OBFS-005 | ROT13 encoding (AST), URL-encoded runs, double-encoding, unicode escape sequences |

See [RULES.md](RULES.md) for the full catalog.

## Configuration

Pass a TOML config file to customize behavior:

```bash
skill-scan scan path/to/skill/ --config scan.toml
```

```toml
[scan]
max_workers = 4      # worker processes for concurrent scanning (0 = auto-detect, max 8)
max_file_size = 500000
max_file_count = 100
```

Custom rules can be authored using the [rule template](src/skill_scan/rules/template.toml).

## Python API

```python
from skill_scan import scan, format_sarif, Severity

result = scan("path/to/skill/")
print(result.verdict)           # Verdict.PASS or Verdict.BLOCK
print(result.suppressed_count)  # number of findings suppressed via # noqa

for finding in result.findings:
    print(f"[{finding.severity.name}] {finding.rule_id}: {finding.description}")

# SARIF output for programmatic use
sarif_output = format_sarif(result)  # returns SARIF v2.1.0 JSON string
```

## Development

```bash
# Install dev dependencies
make install

# Run all quality checks (ruff, mypy, bandit, pytest, custom linters)
make check
```

## License
