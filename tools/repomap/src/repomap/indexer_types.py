"""Data models and AST helpers for the codebase indexer.

Contains the dataclasses used by ``repomap.indexer.Indexer`` to represent
modules, entry points, and type definitions discovered during indexing,
plus pure-function AST analysis helpers that construct those models.
"""

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ModuleInfo:
    """Information about a single module."""

    path: str
    purpose: str
    imports_internal: List[str] = field(default_factory=list)
    imports_external: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "purpose": self.purpose,
            "imports_internal": self.imports_internal,
            "imports_external": self.imports_external,
            "exports": self.exports,
            "size_bytes": self.size_bytes,
        }


@dataclass
class EntryPoint:
    """An entry point into the codebase."""

    type: str  # "cli", "library", "hook"
    file: str
    function: Optional[str] = None
    line: Optional[int] = None
    exports: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {"type": self.type, "file": self.file}
        if self.function:
            result["function"] = self.function
        if self.line:
            result["line"] = self.line
        if self.exports:
            result["exports"] = self.exports
        return result


@dataclass
class TypeInfo:
    """Information about a key type/class."""

    name: str
    file: str
    line: int
    kind: str  # "class", "namedtuple", "dataclass", "function"
    fields: Optional[List[str]] = None
    methods: Optional[List[str]] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
        }
        if self.fields:
            result["fields"] = self.fields
        if self.methods:
            result["methods"] = self.methods
        if self.notes:
            result["notes"] = self.notes
        return result


# ---------------------------------------------------------------------------
# Pure AST analysis helpers
# ---------------------------------------------------------------------------


def extract_first_sentence(text: str) -> str:
    """Extract first sentence from a docstring.

    Args:
        text: Raw docstring text.

    Returns:
        First sentence, capped at 200 characters.
    """
    if not text:
        return ""

    # Split by newlines and take first non-empty line
    lines = text.strip().split("\n")
    first_line = lines[0].strip() if lines else ""

    # Truncate at period if present
    if ". " in first_line:
        first_line = first_line.split(". ")[0] + "."
    elif first_line and not first_line.endswith("."):
        first_line = first_line + "."

    return first_line[:200]  # Cap length


def _extract_all_list(node: ast.Assign) -> Optional[List[str]]:
    """Extract names from an ``__all__ = [...]`` assignment.

    Returns:
        List of exported names, or None if not an __all__ assignment.
    """
    for target in node.targets:
        if isinstance(target, ast.Name) and target.id == "__all__":
            if isinstance(node.value, (ast.List, ast.Tuple)):
                return [
                    elt.value
                    for elt in node.value.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                ]
    return None


def extract_exports(tree: ast.Module) -> List[str]:
    """Extract exported names from a module AST.

    Looks for an ``__all__`` assignment first; falls back to collecting
    top-level public class and function names.
    """
    exports: List[str] = []

    for node in tree.body:
        if isinstance(node, ast.Assign):
            all_names = _extract_all_list(node)
            if all_names is not None:
                return all_names

        if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and not node.name.startswith("_"):
            exports.append(node.name)

    return exports


def extract_dataclass_fields(node: ast.ClassDef) -> List[str]:
    """Extract field names from a dataclass AST node."""
    fields: List[str] = []
    for item in node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            fields.append(item.target.id)
    return fields


def extract_namedtuple_fields(call: ast.Call) -> List[str]:
    """Extract field names from a namedtuple() call AST node."""
    if len(call.args) >= 2:
        arg = call.args[1]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value.split()
        elif isinstance(arg, (ast.List, ast.Tuple)):
            return [
                elt.value
                for elt in arg.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
    return []


def find_main_function(tree: ast.Module) -> Optional[int]:
    """Find the line number of a ``main()`` function in a module AST.

    Returns:
        Line number, or None if no ``main`` function exists.
    """
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            return node.lineno
    return None


def _extract_class_type(node: ast.ClassDef, rel_path: str) -> TypeInfo:
    """Build TypeInfo from a ClassDef node."""
    kind = "class"
    fields: Optional[List[str]] = None

    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id == "dataclass":
            kind = "dataclass"
            fields = extract_dataclass_fields(node)
            break

    method_names = [
        n.name for n in node.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
    ]

    return TypeInfo(
        name=node.name,
        file=rel_path,
        line=node.lineno,
        kind=kind,
        fields=fields,
        methods=method_names[:10] if method_names else None,
    )


def _extract_namedtuple_type(node: ast.Assign, rel_path: str) -> Optional[TypeInfo]:
    """Extract a namedtuple TypeInfo from an assignment, if applicable."""
    for target in node.targets:
        if not (isinstance(target, ast.Name) and isinstance(node.value, ast.Call)):
            continue
        func = node.value.func
        if isinstance(func, ast.Name) and func.id == "namedtuple":
            return TypeInfo(
                name=target.id,
                file=rel_path,
                line=node.lineno,
                kind="namedtuple",
                fields=extract_namedtuple_fields(node.value),
            )
    return None


def extract_types(tree: ast.Module, rel_path: str) -> Dict[str, TypeInfo]:
    """Extract key type definitions from a module AST.

    Returns:
        Mapping of type name to ``TypeInfo``.
    """
    types: Dict[str, TypeInfo] = {}

    for node in tree.body:
        if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            types[node.name] = _extract_class_type(node, rel_path)
        elif isinstance(node, ast.Assign):
            info = _extract_namedtuple_type(node, rel_path)
            if info is not None:
                types[info.name] = info

    return types
