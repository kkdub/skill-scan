"""
Agent-friendly codebase index generator.

Generates structured JSON index files that help AI agents quickly
understand codebase architecture, dependencies, and entry points.

Output: .repomap/index.json
"""

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from repomap.core import RepoMap
from repomap.indexer_types import (
    EntryPoint,
    ModuleInfo,
    TypeInfo,
    extract_exports,
    extract_first_sentence,
    extract_types,
    find_main_function,
)
from repomap.ranking import build_graph
from repomap.tags import Tag


class Indexer:
    """Generates agent-friendly codebase indexes."""

    def __init__(
        self,
        root: Path,
        directories: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> None:
        """Initialize the indexer.

        Args:
            root: Project root directory.
            directories: Directories to index (default: ["src"]).
            exclude_patterns: Patterns to exclude (default: tests, __pycache__).
        """
        self.root = root.resolve()
        self.directories = directories or ["src"]
        self.exclude_patterns = exclude_patterns or [
            "**/tests/**",
            "**/test_*",
            "**/__pycache__/**",
            "**/*.pyc",
        ]

        self._modules: dict[str, ModuleInfo] = {}
        self._dependencies: dict[str, list[str]] = {}
        self._entry_points: list[EntryPoint] = []
        self._types: dict[str, TypeInfo] = {}
        self._all_tags: dict[str, list[Tag]] = {}
        self._internal_modules: set[str] = set()

    def compute_fingerprint(self) -> str:
        """Compute a content-based fingerprint of the source files.

        Hashes sorted (relative_path, content_sha256) pairs so that
        any file addition, removal, or content change alters the digest.
        Uses file contents rather than mtime so the fingerprint is
        identical across machines for the same source tree.

        Returns:
            SHA-256 hex digest string.
        """
        entries: list[str] = []
        for fpath in sorted(self._collect_files()):
            rel = str(fpath.relative_to(self.root)).replace("\\", "/")
            raw = fpath.read_bytes().replace(b"\r\n", b"\n")
            content_hash = hashlib.sha256(raw).hexdigest()
            entries.append(f"{rel}:{content_hash}")

        hasher = hashlib.sha256()
        hasher.update("\n".join(entries).encode("utf-8"))
        return hasher.hexdigest()

    def generate(self) -> dict[str, Any]:
        """Generate the complete index.

        Returns:
            Dictionary ready for JSON serialization.
        """
        # Collect files and extract tags
        files = self._collect_files()
        self._extract_tags(files)

        # Build dependency graph
        self._build_dependencies()

        # Analyze each module
        for fpath in files:
            self._analyze_module(fpath)

        # Detect entry points
        self._detect_entry_points(files)

        # Infer layers
        layers = self._infer_layers()

        # Compute fingerprint for staleness detection
        fingerprint = self.compute_fingerprint()

        # Build the index
        return {
            "version": "1.0",
            "source_fingerprint": fingerprint,
            "indexed_directories": self.directories,
            "entry_points": [ep.to_dict() for ep in self._entry_points],
            "modules": {k: v.to_dict() for k, v in sorted(self._modules.items())},
            "dependencies": {k: sorted(v) for k, v in sorted(self._dependencies.items()) if v},
            "layers": layers,
            "types": {k: v.to_dict() for k, v in sorted(self._types.items())},
        }

    def _collect_files(self) -> list[Path]:
        """Collect Python files from configured directories."""
        files: list[Path] = []
        for directory in self.directories:
            dir_path = self.root / directory
            if not dir_path.exists():
                continue
            for fpath in dir_path.rglob("*.py"):
                if self._should_exclude(fpath):
                    continue
                files.append(fpath)
                module_name = self._path_to_module_name(fpath.relative_to(self.root))
                if module_name:
                    self._internal_modules.add(module_name)
        return sorted(files)

    def _should_exclude(self, fpath: Path) -> bool:
        """Check if a file matches any exclude pattern."""
        rel_str = str(fpath.relative_to(self.root))
        for pattern in self.exclude_patterns:
            if "**" in pattern:
                regex = pattern.replace("**", ".*").replace("*", "[^/]*")
                if re.match(regex, rel_str):
                    return True
            elif pattern.startswith("*") and rel_str.endswith(pattern[1:]):
                return True
        return False

    @staticmethod
    def _path_to_module_name(rel_path: Path) -> str | None:
        """Convert a relative path to a dotted module name."""
        parts = list(rel_path.parts)
        if not parts:
            return None
        if parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]
        if parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts) if parts else None

    def _extract_tags(self, files: list[Path]) -> None:
        """Extract tags from all files using RepoMap."""
        file_strs = [str(f) for f in files]

        with RepoMap(root=str(self.root), verbose=False) as repo_map:
            for fpath in file_strs:
                rel_fname = repo_map.get_rel_fname(fpath)
                tags = repo_map.get_tags(fpath, rel_fname)
                self._all_tags[rel_fname] = tags

    def _build_dependencies(self) -> None:
        """Build the dependency graph from tags."""
        if not self._all_tags:
            return

        G, _defines, _references, _definitions = build_graph(self._all_tags, set())

        # Convert graph edges to dependency mapping
        for rel_fname in self._all_tags:
            deps: set[str] = set()
            if rel_fname in G:
                for _, dest in G.out_edges(rel_fname):
                    if dest != rel_fname:
                        # Normalize path separators to forward slashes
                        deps.add(dest.replace("\\", "/"))
            # Normalize the key as well
            normalized_key = rel_fname.replace("\\", "/")
            self._dependencies[normalized_key] = list(deps)

    def _analyze_module(self, fpath: Path) -> None:
        """Analyze a single module file."""
        rel_path = fpath.relative_to(self.root)
        rel_str = str(rel_path).replace("\\", "/")

        try:
            content = fpath.read_text(encoding="utf-8")
            tree = ast.parse(content)
        except (OSError, SyntaxError):
            return

        # Extract module docstring
        purpose = ast.get_docstring(tree) or ""
        # Take first line/sentence only
        purpose = extract_first_sentence(purpose)

        # Extract imports
        imports_internal: list[str] = []
        imports_external: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._categorize_import(alias.name, imports_internal, imports_external)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self._categorize_import(node.module, imports_internal, imports_external)

        # Extract exports (__all__ or top-level public names)
        exports = extract_exports(tree)

        # Extract key types
        self._types.update(extract_types(tree, rel_str))

        self._modules[rel_str] = ModuleInfo(
            path=rel_str,
            purpose=purpose,
            imports_internal=sorted(set(imports_internal)),
            imports_external=sorted(set(imports_external)),
            exports=exports,
            size_bytes=fpath.stat().st_size,
        )

    def _categorize_import(
        self,
        module_name: str,
        internal: list[str],
        external: list[str],
    ) -> None:
        """Categorize an import as internal or external."""
        top_level = module_name.split(".")[0]

        # Check if it's an internal module
        if top_level in self._internal_modules or any(
            module_name.startswith(m) for m in self._internal_modules
        ):
            internal.append(top_level)
        elif top_level in ("repomap",):  # Package name
            internal.append(module_name.split(".")[-1] if "." in module_name else module_name)
        else:
            external.append(top_level)

    # Maps filename patterns to entry point types requiring a main() function
    _MAIN_ENTRY_TYPES: dict[str, str] = {
        "cli.py": "cli",
        "__main__.py": "cli",
    }

    def _detect_entry_points(self, files: list[Path]) -> None:
        """Detect entry points in the codebase."""
        for fpath in files:
            rel_path = str(fpath.relative_to(self.root)).replace("\\", "/")
            try:
                tree = ast.parse(fpath.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                continue

            # Library entry point: __init__.py with __all__
            if fpath.name == "__init__.py":
                exports = extract_exports(tree)
                if exports:
                    self._entry_points.append(
                        EntryPoint(type="library", file=rel_path, exports=exports)
                    )

            # CLI/hook entry points: files with a main() function
            ep_type = self._MAIN_ENTRY_TYPES.get(fpath.name)
            if ep_type is None and "pre_commit" in fpath.name:
                ep_type = "hook"
            if ep_type:
                main_line = find_main_function(tree)
                if main_line:
                    self._entry_points.append(
                        EntryPoint(type=ep_type, file=rel_path, function="main", line=main_line)
                    )

    def _infer_layers(self) -> dict[str, list[str]]:
        """Infer architectural layers from module structure and dependencies."""
        layers: dict[str, list[str]] = {
            "interface": [],
            "integration": [],
            "core": [],
            "foundation": [],
        }

        self._categorize_by_naming(layers)
        self._categorize_by_dependencies(layers)
        self._categorize_init_files(layers)

        # Sort each layer and remove empties
        for layer in layers:
            layers[layer] = sorted(set(layers[layer]))
        return {k: v for k, v in layers.items() if v}

    def _categorize_by_naming(self, layers: dict[str, list[str]]) -> None:
        """Categorize modules into layers by naming conventions."""
        for rel_path in self._modules:
            if rel_path.endswith("__init__.py"):
                continue
            if "cli" in rel_path or "__main__" in rel_path:
                layers["interface"].append(rel_path)
            elif "integration" in rel_path:
                layers["integration"].append(rel_path)

    def _categorize_by_dependencies(self, layers: dict[str, list[str]]) -> None:
        """Categorize remaining modules into foundation/core by dependency depth.

        Foundation: modules with no internal dependencies.
        Core: all other modules not already placed by naming conventions.
        """
        already_placed = set(layers["interface"] + layers["integration"])

        for rel_path in self._modules:
            if rel_path in already_placed or rel_path.endswith("__init__.py"):
                continue
            # Split by presence of internal dependencies
            if self._dependencies.get(rel_path, []):
                layers["core"].append(rel_path)
            else:
                layers["foundation"].append(rel_path)

    def _categorize_init_files(self, layers: dict[str, list[str]]) -> None:
        """Place __init__.py files into appropriate layers."""
        for rel_path in self._modules:
            if not rel_path.endswith("__init__.py"):
                continue
            if rel_path.count("/") <= 2:
                layers["interface"].append(rel_path)
            else:
                layers["integration"].append(rel_path)


def generate_index(
    root: Path,
    output_dir: Path | None = None,
    directories: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> Path:
    """Generate the codebase index and write to disk.

    Args:
        root: Project root directory.
        output_dir: Output directory (default: root/.repomap).
        directories: Directories to index.
        exclude_patterns: Patterns to exclude.

    Returns:
        Path to the generated index file.
    """
    if output_dir is None:
        output_dir = root / ".repomap"

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "index.json"

    indexer = Indexer(
        root=root,
        directories=directories,
        exclude_patterns=exclude_patterns,
    )

    index = indexer.generate()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
        f.write("\n")

    return output_path


def check_index_freshness(
    root: Path,
    output_dir: Path | None = None,
    directories: list[str] | None = None,
) -> int:
    """Check if the existing index is up-to-date.

    Compares the stored source fingerprint against a freshly computed one.
    If ``directories`` is None, reads ``indexed_directories`` from the
    existing index so the check uses the same scope as the last generation.

    Args:
        root: Project root directory.
        output_dir: Directory containing index.json (default: root/.repomap).
        directories: Override directories to check. If None, uses value
            stored in the index.

    Returns:
        0 if the index is current, 1 if stale or missing.
    """
    if output_dir is None:
        output_dir = root / ".repomap"

    index_path = output_dir / "index.json"
    if not index_path.is_file():
        return 1

    try:
        with open(index_path, "r", encoding="utf-8") as f:
            existing = json.load(f)
    except (OSError, json.JSONDecodeError):
        return 1

    stored_fingerprint = existing.get("source_fingerprint")
    if stored_fingerprint is None:
        return 1

    # Use directories from the index unless explicitly overridden
    if directories is None:
        directories = existing.get("indexed_directories")

    indexer = Indexer(root=root, directories=directories)
    current_fingerprint = indexer.compute_fingerprint()

    return 0 if current_fingerprint == stored_fingerprint else 1
