"""AST-based Python code analyzer — detect unsafe patterns via syntax tree.

Pure module using stdlib ast. No I/O, no logging, no side effects.
Takes a Python source string and returns a list of Finding objects.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import (
    get_call_name,
    has_safe_loader,
    is_subprocess_shell_true,
    try_resolve_string,
)
from skill_scan.models import Finding, Severity

_CATEGORY = "malicious-code"

# Known dangerous function/attribute names used in evasion detection
_DANGEROUS_NAMES = frozenset({"eval", "exec", "system", "popen", "getattr", "__import__"})

_RECOMMENDATIONS: dict[str, str] = {
    "EXEC-002": "Remove dynamic code execution; use safe alternatives with validated inputs",
    "EXEC-006": "Use explicit imports instead of __import__, getattr, or importlib for module loading",
    "EXEC-007": "Use safe alternatives: json, yaml.safe_load, or validated data formats instead of pickle/marshal",
}


def analyze_python(content: str, file_path: str) -> list[Finding]:
    """Analyze Python source for unsafe patterns using AST.

    Parses the source with ast.parse() and walks the tree looking for
    dangerous patterns that regex scanning might miss (especially evasion
    techniques like string concatenation to build dangerous names).

    Returns an empty list on SyntaxError (graceful fallback to regex-only).
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        findings.extend(_detect_unsafe_calls(node, file_path))
        findings.extend(_detect_dynamic_imports(node, file_path))
        findings.extend(_detect_unsafe_deserialization(node, file_path))
        findings.extend(_detect_string_concat_evasion(node, file_path))
        findings.extend(_detect_dynamic_access(node, file_path))
    return findings


_UNSAFE_EXEC_CALLS = frozenset(
    {
        "eval",
        "exec",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execl",
        "os.execvp",
        "os.execvpe",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
    }
)


def _detect_unsafe_calls(node: ast.AST, file_path: str) -> list[Finding]:
    """Detect eval(), exec(), os.system/popen/exec*/spawn*, subprocess shell=True."""
    if not isinstance(node, ast.Call):
        return []

    name = get_call_name(node)

    if name in _UNSAFE_EXEC_CALLS:
        return [
            _make_finding(
                rule_id="EXEC-002",
                severity=Severity.CRITICAL,
                file=file_path,
                line=node.lineno,
                matched_text=f"{name}(",
                description=f"Dynamic code execution — {name}() call detected via AST",
            )
        ]
    if is_subprocess_shell_true(node, name):
        return [
            _make_finding(
                rule_id="EXEC-002",
                severity=Severity.CRITICAL,
                file=file_path,
                line=node.lineno,
                matched_text=f"{name}(shell=True)",
                description="Dynamic code execution — subprocess with shell=True detected via AST",
            )
        ]
    return []


def _detect_dynamic_imports(node: ast.AST, file_path: str) -> list[Finding]:
    """Detect __import__() and importlib.import_module()."""
    if not isinstance(node, ast.Call):
        return []

    name = get_call_name(node)
    if name in ("__import__", "importlib.import_module"):
        return [
            _make_finding(
                rule_id="EXEC-006",
                severity=Severity.HIGH,
                file=file_path,
                line=node.lineno,
                matched_text=f"{name}(",
                description=f"Dynamic indirection — {name}() detected via AST",
            )
        ]
    return []


_UNSAFE_DESER_CALLS = frozenset(
    {
        "pickle.load",
        "pickle.loads",
        "marshal.load",
        "marshal.loads",
        "shelve.open",
        "cloudpickle.loads",
        "dill.loads",
        "yaml.unsafe_load",
    }
)


def _detect_unsafe_deserialization(node: ast.AST, file_path: str) -> list[Finding]:
    """Detect pickle/marshal/shelve/cloudpickle/dill, yaml.load/unsafe_load."""
    if not isinstance(node, ast.Call):
        return []

    name = get_call_name(node)

    if name in _UNSAFE_DESER_CALLS:
        return [
            _make_finding(
                rule_id="EXEC-007",
                severity=Severity.CRITICAL,
                file=file_path,
                line=node.lineno,
                matched_text=f"{name}(",
                description=f"Unsafe deserialization — {name}() detected via AST",
            )
        ]

    # yaml.load — only flag if SafeLoader is NOT used
    if name == "yaml.load" and not has_safe_loader(node):
        return [
            _make_finding(
                rule_id="EXEC-007",
                severity=Severity.CRITICAL,
                file=file_path,
                line=node.lineno,
                matched_text="yaml.load(",
                description="Unsafe deserialization — yaml.load() without SafeLoader detected via AST",
            )
        ]

    return []


def _detect_string_concat_evasion(node: ast.AST, file_path: str) -> list[Finding]:
    """Detect string concatenation building dangerous function names.

    Catches patterns like:
    - 'ev' + 'al'  (BinOp with Add on string constants)
    - ''.join(['e','v','a','l'])  (join on list of char constants)
    - chr(101) + chr(118) + ...  (chr() calls building strings)

    Skips plain ast.Constant nodes — a literal like 'eval' in source code
    is not evasion and must not trigger a finding (R-EFF002).
    """
    if isinstance(node, ast.Constant):
        return []
    resolved = try_resolve_string(node)
    if resolved is not None and resolved in _DANGEROUS_NAMES:
        return [
            _make_finding(
                rule_id="EXEC-002",
                severity=Severity.CRITICAL,
                file=file_path,
                line=getattr(node, "lineno", 0),
                matched_text=f"string evasion building '{resolved}'",
                description=f"String concatenation evasion — builds '{resolved}' via AST",
            )
        ]
    return []


def _detect_dynamic_access(node: ast.AST, file_path: str) -> list[Finding]:
    """Detect getattr() with string concat building dangerous names."""
    if not isinstance(node, ast.Call):
        return []

    name = get_call_name(node)
    if name != "getattr" or len(node.args) < 2:
        return []

    resolved = try_resolve_string(node.args[1])
    if resolved is not None and resolved in _DANGEROUS_NAMES:
        return [
            _make_finding(
                rule_id="EXEC-006",
                severity=Severity.HIGH,
                file=file_path,
                line=node.lineno,
                matched_text=f"getattr(..., '{resolved}')",
                description=f"Dynamic indirection — getattr building '{resolved}' detected via AST",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    rule_id: str,
    severity: Severity,
    file: str,
    line: int,
    matched_text: str,
    description: str,
) -> Finding:
    """Build a Finding for an AST-detected pattern."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=_CATEGORY,
        file=file,
        line=line,
        matched_text=matched_text,
        description=description,
        recommendation=_RECOMMENDATIONS.get(rule_id, "Review and remove unsafe pattern"),
    )
