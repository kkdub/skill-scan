"""
Tag parsing and tree-sitter integration for RepoMap.

The Tag namedtuple is the canonical definition used throughout the package.
"""

import sys
from collections import namedtuple
from typing import Callable, List, Optional

# Canonical Tag definition - import this from here everywhere
Tag = namedtuple("Tag", "rel_fname fname line name kind")


def _capture_kind(capture_name: str) -> Optional[str]:
    """Map a tree-sitter capture name to a tag kind ('def' or 'ref')."""
    if "name.definition" in capture_name:
        return "def"
    if "name.reference" in capture_name:
        return "ref"
    return None


def _process_captures(
    captures: dict,
    rel_fname: str,
    fname: str,
) -> List[Tag]:
    """Convert tree-sitter captures dict into a list of Tags."""
    tags: List[Tag] = []
    for capture_name, nodes in captures.items():
        kind = _capture_kind(capture_name)
        if kind is None:
            continue
        for node in nodes:
            tags.append(
                Tag(
                    rel_fname=rel_fname,
                    fname=fname,
                    line=node.start_point[0] + 1,
                    name=node.text.decode("utf-8") if node.text else "",
                    kind=kind,
                )
            )
    return tags


def get_tags_raw(
    fname: str,
    rel_fname: str,
    get_scm_fname: Callable[[str], Optional[str]],
    read_text: Callable[[str], Optional[str]],
    on_error: Callable[[str], None] = lambda msg: None,
) -> List[Tag]:
    """Parse file to extract tags using Tree-sitter.

    Args:
        fname: Absolute path to the file.
        rel_fname: Relative path for tag metadata.
        get_scm_fname: Callable that maps a language name to a .scm query file path.
        read_text: Callable that reads a file and returns its text content.
        on_error: Callable for error reporting.

    Returns:
        List of Tag namedtuples extracted from the file.
    """
    try:
        from grep_ast import filename_to_lang
        from grep_ast.tsl import get_language, get_parser
        from tree_sitter import Query, QueryCursor
    except ImportError:
        print("Error: grep-ast is required. Install with: pip install grep-ast")
        sys.exit(1)

    lang = filename_to_lang(fname)
    if not lang:
        return []

    try:
        language = get_language(lang)
        parser = get_parser(lang)
    except Exception as err:
        on_error(f"Skipping file {fname}: {err}")
        return []

    scm_fname = get_scm_fname(lang)
    if not scm_fname:
        return []

    code = read_text(fname)
    if not code:
        return []

    try:
        tree = parser.parse(bytes(code, "utf-8"))
        query_text = read_text(scm_fname)
        if not query_text:
            return []

        query = Query(language, query_text)
        cursor = QueryCursor(query)
        captures = cursor.captures(tree.root_node)
        return _process_captures(captures, rel_fname, fname)

    except Exception as e:
        on_error(f"Error parsing {fname}: {e}")
        return []
