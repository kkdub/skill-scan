"""
PageRank graph building and ranking logic for RepoMap.
"""

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from repomap.tags import Tag


def build_graph(
    all_tags: Dict[str, List[Tag]],
    chat_rel_fnames: Set[str],
) -> Tuple[nx.MultiDiGraph, Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, Set[str]]]:
    """Build a directed graph of file references for PageRank.

    Args:
        all_tags: Mapping from relative file path to its list of Tags.
        chat_rel_fnames: Set of relative paths for files currently being edited.

    Returns:
        A tuple of (graph, defines, references, definitions) where:
        - graph: networkx MultiDiGraph with files as nodes and reference edges
        - defines: mapping from symbol name to set of files that define it
        - references: mapping from symbol name to set of files that reference it
        - definitions: mapping from file to set of symbol names it defines
    """
    defines: Dict[str, Set[str]] = defaultdict(set)
    references: Dict[str, Set[str]] = defaultdict(set)
    definitions: Dict[str, Set[str]] = defaultdict(set)

    for rel_fname, tags in all_tags.items():
        for tag in tags:
            if tag.kind == "def":
                defines[tag.name].add(rel_fname)
                definitions[rel_fname].add(tag.name)
            elif tag.kind == "ref":
                references[tag.name].add(rel_fname)

    # Build graph
    G: nx.MultiDiGraph = nx.MultiDiGraph()

    # Add nodes for all files
    for rel_fname in all_tags:
        G.add_node(rel_fname)

    # Add edges based on references
    for name, ref_fnames in references.items():
        def_fnames = defines.get(name, set())
        for ref_fname in ref_fnames:
            for def_fname in def_fnames:
                if ref_fname != def_fname:
                    G.add_edge(ref_fname, def_fname, name=name)

    return G, defines, references, definitions


def rank_files(
    G: nx.MultiDiGraph,
    personalization: Optional[Dict[str, float]] = None,
) -> Dict[str, float]:
    """Run PageRank on the file graph.

    Args:
        G: The file reference graph.
        personalization: Optional personalization vector for PageRank
            (higher values bias rank towards those nodes).

    Returns:
        Mapping from relative file path to its PageRank score.
    """
    if not G.nodes():
        return {}

    try:
        if personalization:
            ranks: Dict[str, float] = nx.pagerank(G, personalization=personalization, alpha=0.85)
            return ranks
        else:
            return {node: 1.0 for node in G.nodes()}
    except nx.NetworkXError:
        # PageRank can fail on graphs with no edges or disconnected components
        return {node: 1.0 for node in G.nodes()}


def _compute_boost(
    tag_name: str,
    rel_fname: str,
    mentioned_idents: Set[str],
    mentioned_fnames: Set[str],
    chat_rel_fnames: Set[str],
) -> float:
    """Compute the relevance boost multiplier for a tag."""
    boost = 1.0
    if tag_name in mentioned_idents:
        boost *= 10.0
    if rel_fname in mentioned_fnames:
        boost *= 5.0
    if rel_fname in chat_rel_fnames:
        boost *= 20.0
    return boost


def rank_tags(
    ranked_files: Dict[str, float],
    all_tags: Dict[str, List[Tag]],
    chat_rel_fnames: Set[str],
    mentioned_fnames: Optional[Set[str]] = None,
    mentioned_idents: Optional[Set[str]] = None,
    exclude_unranked: bool = False,
) -> List[Tuple[float, Tag]]:
    """Produce a ranked list of definition tags using file PageRank scores.

    Args:
        ranked_files: Mapping from rel_fname to PageRank score.
        all_tags: Mapping from rel_fname to list of Tags.
        chat_rel_fnames: Set of relative paths for chat files.
        mentioned_fnames: Set of explicitly mentioned file paths.
        mentioned_idents: Set of explicitly mentioned identifiers.
        exclude_unranked: If True, skip files with near-zero rank.

    Returns:
        List of (score, Tag) tuples sorted by score descending.
    """
    mentioned_fnames = mentioned_fnames or set()
    mentioned_idents = mentioned_idents or set()

    ranked_tags: List[Tuple[float, Tag]] = []

    for rel_fname, tags in all_tags.items():
        file_rank = ranked_files.get(rel_fname, 0.0)
        if exclude_unranked and file_rank <= 0.0001:
            continue

        for tag in tags:
            if tag.kind == "def":
                boost = _compute_boost(
                    tag.name, rel_fname, mentioned_idents, mentioned_fnames, chat_rel_fnames
                )
                ranked_tags.append((file_rank * boost, tag))

    ranked_tags.sort(key=lambda x: x[0], reverse=True)
    return ranked_tags
