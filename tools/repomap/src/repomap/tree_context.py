"""
Aider-compatible tree context rendering.

Provides functions for rendering code snippets with highlighted lines of interest,
compatible with Aider's repo-map output format.
"""

from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from grep_ast import TreeContext

from repomap.tags import Tag


def render_tree_context(
    abs_fname: str,
    rel_fname: str,
    lois: List[int],
    read_text: Callable[[str], Optional[str]],
    tree_context_cache: Optional[Dict[str, TreeContext]] = None,
) -> str:
    """Render a code snippet with specific lines of interest.

    Args:
        abs_fname: Absolute path to the source file.
        rel_fname: Relative path (used for display and caching).
        lois: Line numbers of interest (1-based).
        read_text: Callable that reads a file and returns its content.
        tree_context_cache: Optional dict to cache TreeContext objects.

    Returns:
        Formatted string showing the file with highlighted lines.
    """
    code = read_text(abs_fname)
    if not code:
        return ""

    if tree_context_cache is None:
        tree_context_cache = {}

    try:
        # Create a fresh TreeContext each time since lois differ per call
        tree_context = TreeContext(
            rel_fname,
            code,
            color=False,
        )
        tree_context.add_lines_of_interest(lois)
        tree_context.add_context()
        result: str = tree_context.format()
        return result
    except ValueError:
        # Fallback to simple line extraction
        # TreeContext raises ValueError for unknown language
        lines = code.splitlines()
        result_lines = [f"{rel_fname}:"]

        for loi in sorted(set(lois)):
            if 1 <= loi <= len(lines):
                result_lines.append(f"{loi:4d}: {lines[loi - 1]}")

        return "\n".join(result_lines)


def to_tree(
    tags: List[Tuple[float, Tag]],
    chat_rel_fnames: Set[str],
    root: Path,
    read_text: Callable[[str], Optional[str]],
    tree_context_cache: Optional[Dict[str, TreeContext]] = None,
) -> str:
    """Convert ranked tags to a formatted tree output.

    Args:
        tags: List of (rank, Tag) tuples.
        chat_rel_fnames: Set of relative paths for chat files.
        root: Repository root path.
        read_text: Callable that reads a file and returns its content.
        tree_context_cache: Optional dict to cache TreeContext objects.

    Returns:
        Formatted tree string with ranked code snippets.
    """
    if not tags:
        return ""

    if tree_context_cache is None:
        tree_context_cache = {}

    # Group tags by file
    file_tags: Dict[str, List[Tuple[float, Tag]]] = defaultdict(list)
    for rank, tag in tags:
        file_tags[tag.rel_fname].append((rank, tag))

    # Sort files by importance (max rank of their tags)
    sorted_files = sorted(
        file_tags.items(),
        key=lambda x: max(rank for rank, _tag in x[1]),
        reverse=True,
    )

    tree_parts: List[str] = []

    for rel_fname, file_tag_list in sorted_files:
        lois = [tag.line for _rank, tag in file_tag_list]
        abs_fname = str(root / rel_fname)
        max_rank = max(rank for rank, _tag in file_tag_list)

        rendered = render_tree_context(abs_fname, rel_fname, lois, read_text, tree_context_cache)
        if rendered:
            rendered_lines = rendered.splitlines()
            first_line = rendered_lines[0]
            code_lines = rendered_lines[1:]

            tree_parts.append(
                f"{first_line}\n(Rank value: {max_rank:.4f})\n\n" + "\n".join(code_lines)
            )

    return "\n\n".join(tree_parts)
