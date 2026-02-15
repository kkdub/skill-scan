"""
Pre-commit hook that auto-regenerates .repomap/index.json.

Checks whether the index is stale. If so, regenerates it and
stages the result with ``git add``. Returns 1 so pre-commit
knows the working tree was modified and should re-run checks.
"""

import subprocess
import warnings
from pathlib import Path

from repomap.indexer import check_index_freshness, generate_index


def main() -> int:
    """Regenerate index.json if stale, stage it.

    Uses ``Path(".").resolve()`` as the project root (cwd-based,
    matching the CLI convention).

    Returns:
        0 if the index was already current (no changes).
        1 if the index was regenerated and staged.
    """
    root = Path(".").resolve()

    if check_index_freshness(root) == 0:
        return 0

    # Index is stale or missing -- regenerate
    generate_index(root)

    # Stage the updated index so it gets committed
    try:
        subprocess.run(
            ["git", "add", ".repomap/index.json"],
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        warnings.warn(
            f"Could not stage .repomap/index.json: {exc}",
            stacklevel=2,
        )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
