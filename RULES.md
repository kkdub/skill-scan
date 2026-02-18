# Rules Catalog

All detection rules built into skill-scan.
Pattern-based rules are defined in TOML files under `src/skill_scan/rules/data/`.
Procedural rules are implemented directly in Python modules.

To add a custom rule, copy a section from [template.toml](src/skill_scan/rules/template.toml) into a new `.toml` file or your `--config` file.

**73 rules** across 8 categories.

## Prompt Injection

| Rule ID | Severity | Description | Confidence |
|---------|----------|-------------|------------|
| PI-001 | critical | Direct instruction override — attempts to make the agent ignore its original instructions | stable |
| PI-001-ar | critical | Direct instruction override (Arabic) — attempts to ignore or override instructions | beta |
| PI-001-de | critical | Direct instruction override (German) — attempts to ignore or override instructions | beta |
| PI-001-es | critical | Direct instruction override (Spanish) — attempts to ignore or override instructions | beta |
| PI-001-fr | critical | Direct instruction override (French) — attempts to ignore or override instructions | beta |
| PI-001-ja | critical | Direct instruction override (Japanese) — attempts to ignore or override instructions | beta |
| PI-001-ko | critical | Direct instruction override (Korean) — attempts to ignore or override instructions | beta |
| PI-001-ru | critical | Direct instruction override (Russian) — attempts to ignore or override instructions | beta |
| PI-001-zh | critical | Direct instruction override (Chinese) — attempts to ignore or override instructions | beta |
| PI-002 | high | Safety bypass — attempts to disable safety mechanisms or content filters | stable |
| PI-002-ar | high | Safety bypass (Arabic) — attempts to disable safety mechanisms | beta |
| PI-002-de | high | Safety bypass (German) — attempts to disable safety mechanisms | beta |
| PI-002-es | high | Safety bypass (Spanish) — attempts to disable safety mechanisms | beta |
| PI-002-fr | high | Safety bypass (French) — attempts to disable safety mechanisms | beta |
| PI-002-ja | high | Safety bypass (Japanese) — attempts to disable safety mechanisms | beta |
| PI-002-ko | high | Safety bypass (Korean) — attempts to disable safety mechanisms | beta |
| PI-002-ru | high | Safety bypass (Russian) — attempts to disable safety mechanisms | beta |
| PI-002-zh | high | Safety bypass (Chinese) — attempts to disable safety mechanisms | beta |
| PI-003 | high | Role manipulation — attempts to alter the agent's assigned role or persona | stable |
| PI-003-ar | high | Role manipulation (Arabic) — attempts to alter the agent's role | beta |
| PI-003-de | high | Role manipulation (German) — attempts to alter the agent's role | beta |
| PI-003-es | high | Role manipulation (Spanish) — attempts to alter the agent's role | beta |
| PI-003-fr | high | Role manipulation (French) — attempts to alter the agent's role | beta |
| PI-003-ja | high | Role manipulation (Japanese) — attempts to alter the agent's role | beta |
| PI-003-ko | high | Role manipulation (Korean) — attempts to alter the agent's role | beta |
| PI-003-ru | high | Role manipulation (Russian) — attempts to alter the agent's role | beta |
| PI-003-zh | high | Role manipulation (Chinese) — attempts to alter the agent's role | beta |
| PI-004a | medium | Directional overrides — Unicode bidi control characters that can reorder visible text | stable |
| PI-004b | info | Zero-width characters — invisible Unicode characters that may hide content | stable |
| PI-005 | medium | HTML comment injection — hidden instructions embedded in HTML comments | stable |
| PI-006 | medium | Steganographic encoding — hidden instructions encoded in base64, hex, or other encodings | stable |
| PI-007 | medium | Script mixing — Cyrillic homoglyphs adjacent to Latin characters (potential homoglyph attack) | stable |
| PI-008 | medium | Short base64 decode — inline base64-encoded payload in a decode call may hide instructions | stable |
| PI-009 | medium | Script mixing — Greek homoglyphs adjacent to Latin characters (potential homoglyph attack) | stable |

## Malicious Code

| Rule ID | Severity | Description | Confidence |
|---------|----------|-------------|------------|
| EXEC-001 | critical | Remote code execution — downloads piped directly to a shell interpreter | stable |
| EXEC-002 | critical | Dynamic code execution — eval/exec/os.system/subprocess with shell=True | stable |
| EXEC-003 | high | Obfuscated payload — base64/hex-decoded content executed via shell or interpreter | stable |
| EXEC-004 | high | Persistence mechanism — scheduled tasks, startup entries, or shell profile modifications | stable |
| EXEC-005 | high | Suspicious binary download — executable or installer download instructions | stable |
| EXEC-006 | high | Dynamic indirection — runtime module import or attribute lookup bypasses static analysis | stable |
| EXEC-007 | critical | Unsafe deserialization — pickle, marshal, or unsafe YAML loading enables arbitrary code execution | stable |
| EXEC-008 | high | PowerShell cradle or LOLBin download — uses system tools to fetch and execute remote payloads | stable |
| EXEC-009 | critical | Multi-line encoded execution — exec/eval of base64-decoded content spanning multiple lines | stable |
| EXEC-010 | high | Dynamic code execution with strict exclusion — eval/exec calls resistant to comment-based suppression | stable |
| JSEXEC-001 | critical | Node.js code execution -- child_process, spawn, or dynamic Function constructor | stable |
| JSEXEC-002 | critical | JavaScript eval and dynamic execution -- eval, string setTimeout/setInterval, DOM injection | stable |
| JSEXEC-003 | high | Script injection and dynamic loading -- external scripts, dynamic import/require | stable |

## Data Exfiltration

| Rule ID | Severity | Description | Confidence |
|---------|----------|-------------|------------|
| EXFIL-001 | critical | Silent outbound requests — covert data upload via curl, wget, or similar tools | stable |
| EXFIL-002 | high | Sensitive path access — reading private keys, credentials, or browser data | stable |
| EXFIL-003 | high | Webhook/C2 patterns — data exfiltration via webhook endpoints or callback URLs | stable |
| EXFIL-004 | high | Environment harvesting — bulk access to environment variables | stable |
| EXFIL-005 | high | Python HTTP client exfiltration — data sent via requests, httpx, urllib, or aiohttp | stable |
| EXFIL-006 | high | Raw socket and DNS exfiltration — data sent via low-level sockets or DNS queries | stable |
| EXFIL-007 | medium | Mail and messaging exfiltration — data sent via SMTP, SES, or WebSocket | stable |

## Credential Exposure

| Rule ID | Severity | Description | Confidence |
|---------|----------|-------------|------------|
| CRED-001 | critical | Hardcoded secrets — API keys, tokens, or private keys embedded directly in source | stable |
| CRED-002 | high | Credentials in LLM context — instructions to pass secrets through conversation | stable |
| CRED-003 | high | Plaintext password patterns — credentials assigned as string literals in code | stable |

## Supply Chain

| Rule ID | Severity | Description | Confidence |
|---------|----------|-------------|------------|
| SC-001 | medium | Remote instruction fetching — SKILL.md or config loaded from external URL (content can change post-review) | stable |
| SC-002 | medium | Unpinned dependencies — pip install without version pin allows supply chain attacks | stable |
| SC-003 | medium | Broad filesystem access — path traversal or absolute paths to system directories | stable |
| SC-004 | high | Social engineering prerequisites — ClickFix pattern coercing users to run terminal commands | stable |

## Tool Abuse

| Rule ID | Severity | Description | Confidence |
|---------|----------|-------------|------------|
| TOOL-001 | high | Destructive file operations -- rm -rf /, disk overwrite, or filesystem format commands | stable |
| TOOL-002 | high | Privilege escalation instructions -- overly permissive chmod, root shell, or admin group modification | stable |
| TOOL-003 | medium | Tool chaining abuse -- dangerous command sequences that chain execution with deletion or device writes | stable |

## File Safety

| Rule ID | Severity | Description | Confidence |
|---------|----------|-------------|------------|
| FS-001 | medium | File is not valid UTF-8 and was skipped | stable |
| FS-002 | high | Binary file detected in skill directory | stable |
| FS-003 | medium | Unknown file extension not in allowed list | stable |
| FS-004 | high | Symlink points outside the skill directory | stable |
| FS-005 | medium | File exceeds configured size limit | stable |
| FS-006 | medium | Total skill size exceeds configured limit | stable |
| FS-007 | medium | File count exceeds configured limit | stable |
| FS-008 | medium | File could not be read (OS error) | stable |

## Schema Validation

| Rule ID | Severity | Description | Confidence |
|---------|----------|-------------|------------|
| SV-001 | medium | SKILL.md frontmatter validation failed | stable |

---

*Generated by `scripts/generate_rules_catalog.py`. Do not edit manually.*
