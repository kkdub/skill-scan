"""
Post-commit hook that auto-regenerates .repomap/index.json.

Runs after each successful commit to keep the local index fresh.
The updated index is never staged or committed — it stays as an
unstaged working-tree change, avoiding conflicts with other hooks
(e.g. end-of-file-fixer).
"""

from pathlib import Path

from repomap.indexer import check_index_freshness, generate_index


def main() -> int:
    """Regenerate index.json if stale, without staging it.

    Uses ``Path(".").resolve()`` as the project root (cwd-based,
    matching the CLI convention).

    Returns:
        0 always — the hook never fails. Regeneration is a silent
        side-effect that keeps the local index fresh.
    """
    root = Path(".").resolve()

    if check_index_freshness(root) == 0:
        return 0

    # Index is stale or missing -- regenerate (but don't stage)
    generate_index(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
