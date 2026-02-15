"""
RepoMap class -- orchestration layer.

Coordinates tag extraction, ranking, and rendering to produce
repository maps.  Uses PageRank-based relevance scoring to select
the most important code symbols for a given context window.
"""

import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from repomap.cache import (
    close_cache,
    get_cached_tags,
    load_cache,
    make_cache_dir_name,
    reset_cache,
    set_cached_tags,
)
from repomap.io import default_read_text, get_mtime
from repomap.languages import get_scm_fname
from repomap.models import FileReport
from repomap.ranking import build_graph, rank_files, rank_tags
from repomap.tags import Tag, get_tags_raw
from repomap.tokens import default_token_counter, sampled_token_count
from repomap.tree_context import to_tree


class RepoMap:
    """Main class for generating repository maps.

    Accepts dependencies via constructor to avoid hard coupling:
    - token_counter: Callable[[str], int]
    - cache_dir: Path | None (defaults to .repomap-cache/)
    """

    def __init__(
        self,
        map_tokens: int = 1024,
        root: Optional[str] = None,
        token_counter: Callable[[str], int] = default_token_counter,
        file_reader: Callable[[str], Optional[str]] = default_read_text,
        output_handlers: Optional[Dict[str, Callable[..., None]]] = None,
        repo_content_prefix: Optional[str] = None,
        verbose: bool = False,
        max_context_window: Optional[int] = None,
        map_mul_no_files: int = 8,
        refresh: str = "auto",
        exclude_unranked: bool = False,
        cache_dir: Optional[Path] = None,
    ) -> None:
        """Initialize RepoMap instance."""
        self.map_tokens = map_tokens
        self.max_map_tokens = map_tokens
        self.root = Path(root or os.getcwd()).resolve()
        self.token_counter = token_counter
        self.file_reader = file_reader
        self.repo_content_prefix = repo_content_prefix
        self.verbose = verbose
        self.max_context_window = max_context_window
        self.map_mul_no_files = map_mul_no_files
        self.refresh = refresh
        self.exclude_unranked = exclude_unranked

        # Output handlers
        if output_handlers is None:
            output_handlers = {
                "info": print,
                "warning": print,
                "error": print,
            }
        self.output_handlers = output_handlers

        # In-memory caches
        self.tree_context_cache: Dict[str, Any] = {}
        self.map_cache: Dict[tuple, Tuple[Optional[str], FileReport]] = {}

        # Persistent tags cache
        if cache_dir is None:
            cache_dir = self.root / make_cache_dir_name()
        self._cache_dir = cache_dir
        self._tags_cache = load_cache(
            self._cache_dir,
            on_warning=self.output_handlers["warning"],
        )

    def close(self) -> None:
        """Close the tags cache and release resources."""
        close_cache(self._tags_cache)

    def __enter__(self) -> "RepoMap":
        """Support context manager usage."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close resources when exiting context."""
        self.close()

    # ------------------------------------------------------------------
    # Token counting
    # ------------------------------------------------------------------

    def token_count(self, text: str) -> int:
        """Count tokens in text with sampling optimisation for long texts."""
        return sampled_token_count(text, self.token_counter)

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def get_rel_fname(self, fname: str) -> str:
        """Get relative filename from absolute path."""
        try:
            return str(Path(fname).relative_to(self.root))
        except ValueError:
            return fname

    # ------------------------------------------------------------------
    # Tag extraction (with cache)
    # ------------------------------------------------------------------

    def get_tags(self, fname: str, rel_fname: str) -> List[Tag]:
        """Get tags for a file, using cache when possible."""
        file_mtime = get_mtime(fname)
        if file_mtime is None:
            return []

        cached = get_cached_tags(self._tags_cache, fname, file_mtime)
        if cached is not None:
            return cached

        tags = get_tags_raw(
            fname,
            rel_fname,
            get_scm_fname=get_scm_fname,
            read_text=self.file_reader,
            on_error=self.output_handlers["error"],
        )

        set_cached_tags(self._tags_cache, fname, file_mtime, tags)
        return tags

    def _reset_tags_cache(self) -> None:
        """Handle tags cache errors by resetting."""
        self._tags_cache = reset_cache(
            self._cache_dir,
            on_warning=self.output_handlers["warning"],
        )

    # ------------------------------------------------------------------
    # Ranking
    # ------------------------------------------------------------------

    def get_ranked_tags(
        self,
        chat_fnames: List[str],
        other_fnames: List[str],
        mentioned_fnames: Optional[Set[str]] = None,
        mentioned_idents: Optional[Set[str]] = None,
    ) -> Tuple[List[Tuple[float, Tag]], FileReport]:
        """Get ranked tags using PageRank algorithm with file report."""
        if not chat_fnames and not other_fnames:
            return [], FileReport({}, 0, 0, 0)

        mentioned_fnames = mentioned_fnames or set()
        mentioned_idents = mentioned_idents or set()

        chat_fnames = [str(Path(f).resolve()) for f in chat_fnames]
        other_fnames = [str(Path(f).resolve()) for f in other_fnames]

        all_fnames = list(set(chat_fnames + other_fnames))
        chat_rel_fnames = {self.get_rel_fname(f) for f in chat_fnames}

        all_tags, personalization, included, excluded, stats = self._collect_file_tags(
            all_fnames, chat_fnames
        )

        G, _defines, _references, _definitions = build_graph(all_tags, chat_rel_fnames)

        if not G.nodes():
            return [], FileReport(excluded, stats[0], stats[1], len(all_fnames))

        ranked_files = rank_files(G, personalization or None)

        self._update_excluded_info(excluded, included, chat_fnames, other_fnames)

        file_report = FileReport(
            excluded=excluded,
            definition_matches=stats[0],
            reference_matches=stats[1],
            total_files_considered=len(all_fnames),
        )

        ranked = rank_tags(
            ranked_files,
            all_tags,
            chat_rel_fnames,
            mentioned_fnames,
            mentioned_idents,
            self.exclude_unranked,
        )
        return ranked, file_report

    def _collect_file_tags(
        self,
        all_fnames: List[str],
        chat_fnames: List[str],
    ) -> Tuple[Dict[str, List[Tag]], Dict[str, float], List[str], Dict[str, str], Tuple[int, int]]:
        """Collect tags per file, tracking included/excluded files and stats."""
        all_tags: Dict[str, List[Tag]] = {}
        personalization: Dict[str, float] = {}
        included: List[str] = []
        excluded: Dict[str, str] = {}
        total_defs = 0
        total_refs = 0

        for fname in all_fnames:
            rel_fname = self.get_rel_fname(fname)
            if not os.path.exists(fname):
                excluded[fname] = "File not found"
                self.output_handlers["warning"](f"Repo-map can't include {fname}: File not found")
                continue

            included.append(fname)
            tags = self.get_tags(fname, rel_fname)
            all_tags[rel_fname] = tags
            total_defs += sum(1 for t in tags if t.kind == "def")
            total_refs += sum(1 for t in tags if t.kind == "ref")

            if fname in chat_fnames:
                personalization[rel_fname] = 100.0

        return all_tags, personalization, included, excluded, (total_defs, total_refs)

    @staticmethod
    def _update_excluded_info(
        excluded: Dict[str, str],
        included: List[str],
        chat_fnames: List[str],
        other_fnames: List[str],
    ) -> None:
        """Update excluded dict with status labels."""
        for fname in set(chat_fnames + other_fnames):
            if fname in excluded:
                excluded[fname] = f"[EXCLUDED] {excluded[fname]}"
            elif fname not in included:
                excluded[fname] = "[NOT PROCESSED] File not included in final processing"

    # ------------------------------------------------------------------
    # Map generation
    # ------------------------------------------------------------------

    def get_ranked_tags_map(
        self,
        chat_fnames: List[str],
        other_fnames: List[str],
        max_map_tokens: int,
        mentioned_fnames: Optional[Set[str]] = None,
        mentioned_idents: Optional[Set[str]] = None,
        force_refresh: bool = False,
    ) -> Tuple[Optional[str], FileReport]:
        """Get the ranked tags map with caching."""
        cache_key = (
            tuple(sorted(chat_fnames)),
            tuple(sorted(other_fnames)),
            max_map_tokens,
            tuple(sorted(mentioned_fnames or [])),
            tuple(sorted(mentioned_idents or [])),
        )

        if not force_refresh and cache_key in self.map_cache:
            return self.map_cache[cache_key]

        result = self._get_ranked_tags_map_uncached(
            chat_fnames,
            other_fnames,
            max_map_tokens,
            mentioned_fnames,
            mentioned_idents,
        )

        self.map_cache[cache_key] = result
        return result

    def _get_ranked_tags_map_uncached(
        self,
        chat_fnames: List[str],
        other_fnames: List[str],
        max_map_tokens: int,
        mentioned_fnames: Optional[Set[str]] = None,
        mentioned_idents: Optional[Set[str]] = None,
    ) -> Tuple[Optional[str], FileReport]:
        """Generate the ranked tags map without caching."""
        ranked_tags, file_report = self.get_ranked_tags(
            chat_fnames, other_fnames, mentioned_fnames, mentioned_idents
        )

        if not ranked_tags:
            return None, file_report

        chat_rel_fnames = {self.get_rel_fname(f) for f in chat_fnames}

        def try_tags(num_tags: int) -> Tuple[Optional[str], int]:
            if num_tags <= 0:
                return None, 0

            selected_tags = ranked_tags[:num_tags]
            tree_output = to_tree(
                selected_tags,
                chat_rel_fnames,
                self.root,
                self.file_reader,
                self.tree_context_cache,
            )

            if not tree_output:
                return None, 0

            tokens = self.token_count(tree_output)
            return tree_output, tokens

        # Binary search for optimal number of tags
        left, right = 0, len(ranked_tags)
        best_tree: Optional[str] = None

        while left <= right:
            mid = (left + right) // 2
            tree_output, tokens = try_tags(mid)

            if tree_output and tokens <= max_map_tokens:
                best_tree = tree_output
                left = mid + 1
            else:
                right = mid - 1

        return best_tree, file_report

    def _effective_max_tokens(self, chat_files: List[str]) -> int:
        """Compute effective max map tokens, expanding when no chat files."""
        max_tokens = self.max_map_tokens
        if not chat_files and self.max_context_window:
            available = self.max_context_window - 1024
            max_tokens = min(max_tokens * self.map_mul_no_files, available)
        return max_tokens

    def get_repo_map(
        self,
        chat_files: Optional[List[str]] = None,
        other_files: Optional[List[str]] = None,
        mentioned_fnames: Optional[Set[str]] = None,
        mentioned_idents: Optional[Set[str]] = None,
        force_refresh: bool = False,
    ) -> Tuple[Optional[str], FileReport]:
        """Generate the repository map with file report."""
        chat_files = chat_files or []
        other_files = other_files or []
        empty_report = FileReport({}, 0, 0, 0)

        if self.max_map_tokens <= 0 or not other_files:
            return None, empty_report

        try:
            map_string, file_report = self.get_ranked_tags_map(
                chat_files,
                other_files,
                self._effective_max_tokens(chat_files),
                mentioned_fnames,
                mentioned_idents,
                force_refresh,
            )
        except RecursionError:
            self.output_handlers["error"]("Disabling repo map, git repo too large?")
            self.max_map_tokens = 0
            return None, empty_report

        if map_string is None:
            return None, file_report

        if self.verbose:
            tokens = self.token_count(map_string)
            self.output_handlers["info"](f"Repo-map: {tokens / 1024:.1f} k-tokens")

        # Prepend user-configured prefix (e.g. "Here are the {other}files:")
        other = "other " if chat_files else ""
        prefix = self.repo_content_prefix.format(other=other) if self.repo_content_prefix else ""
        return prefix + map_string, file_report
