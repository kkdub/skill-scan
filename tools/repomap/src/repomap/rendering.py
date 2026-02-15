"""
Output formatting for RepoMap.

Provides TreeRenderer for generating annotated directory trees
suitable for CLAUDE.md / AGENTS.md files.

For Aider-compatible ranked code snippet output, see tree_context.py.
"""

from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional, Set, Tuple

from repomap.tags import Tag


def _format_size(size_bytes: int) -> str:
    """Format a file size in human-readable form.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Formatted string like "500B", "3.2KB", "2.4MB".
    """
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f}MB"


class _TreeNode:
    """Internal tree node for building directory structure."""

    def __init__(self, name: str, is_dir: bool = False) -> None:
        self.name = name
        self.is_dir = is_dir
        self.children: Dict[str, "_TreeNode"] = {}
        self.symbols: List[str] = []
        self.file_size: Optional[int] = None

    def get_or_create_child(self, name: str, is_dir: bool = False) -> "_TreeNode":
        """Get existing child or create a new one."""
        if name not in self.children:
            self.children[name] = _TreeNode(name, is_dir=is_dir)
        return self.children[name]

    def sorted_children(self) -> List["_TreeNode"]:
        """Return children sorted: directories first, then files, alphabetically."""
        dirs = sorted(
            [c for c in self.children.values() if c.is_dir],
            key=lambda n: n.name,
        )
        files = sorted(
            [c for c in self.children.values() if not c.is_dir],
            key=lambda n: n.name,
        )
        return dirs + files


class TreeRenderer:
    """Renders an annotated directory tree for CLAUDE.md / AGENTS.md.

    Groups ranked tags by file, shows directory structure with file sizes
    and top-N symbols per file.

    Args:
        root: Root directory path.
        tags: List of (rank, Tag) tuples from PageRank.
        file_sizes: Mapping from relative file path to size in bytes.
        max_depth: Maximum directory depth to display (0 = unlimited).
        max_symbols_per_file: Maximum number of symbols to show per file.
        token_budget: Token budget for output (0 = unlimited).
        token_counter: Callable to count tokens in a string.
        show_size: Whether to show file sizes.
    """

    def __init__(
        self,
        root: Path,
        tags: List[Tuple[float, Tag]],
        file_sizes: Optional[Dict[str, int]] = None,
        max_depth: int = 3,
        max_symbols_per_file: int = 5,
        token_budget: int = 0,
        token_counter: Optional[Callable[[str], int]] = None,
        show_size: bool = True,
    ) -> None:
        self.root = root
        self.tags = tags
        self.file_sizes = file_sizes or {}
        self.max_depth = max_depth
        self.max_symbols_per_file = max_symbols_per_file
        self.token_budget = token_budget
        self.token_counter = token_counter
        self.show_size = show_size

    def render(self) -> str:
        """Render the annotated directory tree.

        Returns:
            Formatted tree string showing directory structure, file sizes,
            and key symbols per file.
        """
        if not self.tags:
            return ""

        all_files, file_symbols = self._group_tags_by_file()
        top_symbols = self._select_top_symbols(file_symbols)
        tree_root = self._build_tree(all_files, top_symbols)

        lines: List[str] = []
        self._render_node(tree_root, lines, prefix="", is_root=True)
        result = "\n".join(lines)

        if self.token_budget > 0:
            result = self._apply_budget(result)

        return result

    def _group_tags_by_file(self) -> Tuple[Set[str], Dict[str, List[Tuple[float, Tag]]]]:
        """Group tags by file, separating definitions for symbol extraction.

        Returns:
            Tuple of (all_files set, file_symbols dict with definition tags only).
        """
        file_symbols: Dict[str, List[Tuple[float, Tag]]] = defaultdict(list)
        all_files: Set[str] = set()

        for rank, tag in self.tags:
            all_files.add(tag.rel_fname)
            if tag.kind == "def":
                file_symbols[tag.rel_fname].append((rank, tag))

        return all_files, file_symbols

    def _select_top_symbols(
        self, file_symbols: Dict[str, List[Tuple[float, Tag]]]
    ) -> Dict[str, List[str]]:
        """Select top-N symbols per file by rank.

        Args:
            file_symbols: Dict mapping file paths to ranked definition tags.

        Returns:
            Dict mapping file paths to lists of symbol names.
        """
        top_symbols: Dict[str, List[str]] = {}
        for rel_fname, ranked_tags in file_symbols.items():
            ranked_tags.sort(key=lambda x: x[0], reverse=True)
            seen: Set[str] = set()
            symbols: List[str] = []
            for _rank, tag in ranked_tags:
                if tag.name not in seen and len(symbols) < self.max_symbols_per_file:
                    seen.add(tag.name)
                    symbols.append(tag.name)
            top_symbols[rel_fname] = symbols
        return top_symbols

    def _build_tree(self, all_files: Set[str], top_symbols: Dict[str, List[str]]) -> _TreeNode:
        """Build tree structure from files and their symbols.

        Args:
            all_files: Set of all file paths to include.
            top_symbols: Dict mapping file paths to symbol names.

        Returns:
            Root tree node with populated children.
        """
        tree_root = _TreeNode("", is_dir=True)
        for rel_fname in all_files:
            self._add_file_to_tree(tree_root, rel_fname, top_symbols)
        return tree_root

    def _add_file_to_tree(
        self, tree_root: _TreeNode, rel_fname: str, top_symbols: Dict[str, List[str]]
    ) -> None:
        """Add a single file path to the tree structure.

        Args:
            tree_root: Root node of the tree.
            rel_fname: Relative file path to add.
            top_symbols: Dict mapping file paths to symbol names.
        """
        parts = PurePosixPath(rel_fname).parts

        if self.max_depth > 0 and len(parts) > self.max_depth:
            # Truncate: only show directory nodes up to max_depth
            node = tree_root
            for part in parts[: self.max_depth]:
                node = node.get_or_create_child(part, is_dir=True)
            return

        node = tree_root
        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1
            if is_last:
                child = node.get_or_create_child(part, is_dir=False)
                child.file_size = self.file_sizes.get(rel_fname)
                child.symbols = top_symbols.get(rel_fname, [])
            else:
                node = node.get_or_create_child(part, is_dir=True)

    def _render_node(
        self,
        node: _TreeNode,
        lines: List[str],
        prefix: str,
        is_root: bool = False,
    ) -> None:
        """Recursively render a tree node and its children.

        Args:
            node: The tree node to render.
            lines: List to append output lines to.
            prefix: Current indentation prefix for tree drawing.
            is_root: Whether this is the root node.
        """
        if is_root:
            # Render children of root directly
            children = node.sorted_children()
            for i, child in enumerate(children):
                is_last = i == len(children) - 1
                self._render_child(child, lines, prefix, is_last)
        else:
            pass  # Should not be called with is_root=False on this level

    def _render_child(
        self,
        node: _TreeNode,
        lines: List[str],
        prefix: str,
        is_last: bool,
    ) -> None:
        """Render a child node with proper tree connectors.

        Args:
            node: The child node to render.
            lines: List to append output lines to.
            prefix: Current indentation prefix.
            is_last: Whether this is the last child in its parent.
        """
        connector = "\u2514\u2500\u2500" if is_last else "\u251c\u2500\u2500"  # └── or ├──
        child_prefix = prefix + ("    " if is_last else "\u2502   ")  # │

        if node.is_dir:
            lines.append(f"{prefix}{connector} {node.name}/")
            children = node.sorted_children()
            for i, child in enumerate(children):
                child_is_last = i == len(children) - 1
                self._render_child(child, lines, child_prefix, child_is_last)
        else:
            # File node
            size_str = ""
            if self.show_size and node.file_size is not None:
                size_str = f" ({_format_size(node.file_size)})"
            lines.append(f"{prefix}{connector} {node.name}{size_str}")

            # Add symbols
            for symbol in node.symbols:
                lines.append(f"{child_prefix}- {symbol}")

    def _apply_budget(self, result: str) -> str:
        """Truncate output to fit within token budget.

        Args:
            result: The full rendered output.

        Returns:
            Truncated output that fits within the token budget.
        """
        counter = self.token_counter
        if counter is None:
            # Default: estimate ~4 chars per token
            counter = lambda text: len(text) // 4  # noqa: E731

        if counter(result) <= self.token_budget:
            return result

        # Truncate line by line, keeping as much as fits
        lines = result.splitlines()
        kept_lines: List[str] = []
        for line in lines:
            candidate = "\n".join(kept_lines + [line])
            if counter(candidate) > self.token_budget:
                break
            kept_lines.append(line)

        return "\n".join(kept_lines)


# Re-export for backwards compatibility
def render_tree_context(
    abs_fname: str,
    rel_fname: str,
    lois: List[int],
    read_text: Callable[[str], Optional[str]],
    tree_context_cache: Optional[Dict[str, "object"]] = None,
) -> str:
    """Render a code snippet with specific lines of interest.

    Deprecated: Import from repomap.tree_context instead.
    """
    from repomap.tree_context import render_tree_context as _render_tree_context

    return _render_tree_context(abs_fname, rel_fname, lois, read_text, tree_context_cache)


def to_tree(
    tags: List[Tuple[float, Tag]],
    chat_rel_fnames: Set[str],
    root: Path,
    read_text: Callable[[str], Optional[str]],
    tree_context_cache: Optional[Dict[str, "object"]] = None,
) -> str:
    """Convert ranked tags to a formatted tree output.

    Deprecated: Import from repomap.tree_context instead.
    """
    from repomap.tree_context import to_tree as _to_tree

    return _to_tree(tags, chat_rel_fnames, root, read_text, tree_context_cache)
