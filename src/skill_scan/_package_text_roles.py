"""File-role classification and snippet extraction for package text analysis."""

from __future__ import annotations

import re

FileRole = str

_SCRIPT_SUFFIXES = frozenset({".py", ".sh", ".bash", ".zsh", ".ps1", ".js", ".ts"})
_CONFIG_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".jinja2"})
_DOC_SUFFIXES = frozenset({".md", ".txt", ".rst"})
_REFERENCE_MARKERS = (
    "reference",
    "references",
    "example",
    "examples",
    "sample",
    "samples",
    "fixture",
    "fixtures",
)
_FENCED_BLOCK_RE = re.compile(r"```[^\n`]*\n(.*?)```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`([^`\n]{4,200})`")
_COMMAND_LINE_RE = re.compile(r"(?im)^\s*(?:\$|PS>|cmd>)?\s*(curl|wget|bash|sh|python|pwsh|powershell)\b.+$")
_COMMAND_HINTS = (
    "curl ",
    "wget ",
    "pip install",
    "python ",
    "bash ",
    "sh ",
    "powershell ",
    "invoke-webrequest",
)


def classify_file_role(relative_path: str) -> FileRole:
    """Classify a file into a package-analysis role."""
    lowered = relative_path.lower()
    if lowered == "skill.md":
        return "entrypoint"
    if any(part in lowered for part in _REFERENCE_MARKERS):
        return "reference"
    suffix = lowered[lowered.rfind(".") :] if "." in lowered else ""
    if suffix in _SCRIPT_SUFFIXES:
        return "script"
    if suffix in _CONFIG_SUFFIXES:
        return "config"
    if suffix in _DOC_SUFFIXES:
        return "support-doc"
    return "support-doc"


def extract_command_snippets(content: str) -> list[str]:
    """Extract likely command snippets from markdown, docs, or scripts."""
    snippets = [m.group(1).strip() for m in _FENCED_BLOCK_RE.finditer(content) if m.group(1).strip()]
    snippets.extend(m.group(1).strip() for m in _INLINE_CODE_RE.finditer(content))
    snippets.extend(m.group(0).strip() for m in _COMMAND_LINE_RE.finditer(content))
    return snippets


def has_command(snippets: list[str]) -> bool:
    """Return True when any extracted snippet looks command-like."""
    return any(_looks_command_like(snippet) for snippet in snippets)


def _looks_command_like(snippet: str) -> bool:
    lowered = snippet.lower()
    return any(token in lowered for token in _COMMAND_HINTS)
