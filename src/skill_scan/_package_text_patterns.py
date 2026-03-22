"""Regex patterns for package text signal detection."""

from __future__ import annotations

import re

COERCION_RE = re.compile(
    r"(?is)(copy|paste|run|execute|enter|type)\s+(?:this|the following)?\s+"
    r"(command|script|code|snippet)|fix\s+.*?\s+by\s+running|open\s+your\s+(terminal|shell|console).*?(run|paste)"
)
SECRET_REQUEST_RE = re.compile(
    r"(?is)(provide|paste|share|send|upload|enter|set)\s+.*?"
    r"(api[_ -]?key|token|secret|password|cookie|private key|ssh key|\.env)"
)
REMOTE_SOURCE_RE = re.compile(
    r"(?is)(source|config[_-]?url|instruction[_-]?url|skill[_-]?url|manifest[_-]?url)\s*[:=]\s*https?://"
)
REMOTE_BOOTSTRAP_RE = re.compile(
    r"(?is)(curl|wget|invoke-webrequest|iwr|irm)\b.*https?://|https?://.*\|\s*(bash|sh|zsh|python|powershell|pwsh)"
)
PIPE_TO_SHELL_RE = re.compile(r"(?is)https?://.*\|\s*(bash|sh|zsh|python|powershell|pwsh)")
WARNING_CONTEXT_RE = re.compile(r"(?i)\b(never|do not|don't|avoid|warning|unsafe|untrusted)\b")
SETUP_WORD_RE = re.compile(r"(?i)\b(setup|diagnostic|repair|bootstrap|fix|install)\b")
