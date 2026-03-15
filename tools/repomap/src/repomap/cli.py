"""
CLI entry point for RepoMap.

Provides subcommands:
  repomap index             - Generate agent-friendly JSON index to .repomap/
  repomap search <query>    - Find symbols by name using tree-sitter AST
  repomap check             - Check if .repomap/index.json is stale (exit 1 if stale)
"""

import argparse
import os
import sys
from pathlib import Path

from repomap.core import RepoMap
from repomap.indexer import check_index_freshness, generate_index


def find_src_files(directory: str) -> list[str]:
    """Find source files in a directory."""
    if not Path(directory).is_dir():
        return [directory] if Path(directory).is_file() else []

    src_files: list[str] = []
    skip_dirs = {"node_modules", "__pycache__", "venv", "env"}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in skip_dirs]
        for file in files:
            if not file.startswith("."):
                src_files.append(str(Path(root) / file))

    return src_files


def _add_index_subparser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add the 'index' subcommand to the parser."""
    index_parser = subparsers.add_parser(
        "index", help="Generate agent-friendly JSON index to .repomap/"
    )
    index_parser.add_argument(
        "--directories",
        nargs="+",
        default=["src", "lib"],
        help="Directories to index (default: src lib)",
    )
    index_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory (default: .repomap)",
    )


def _add_search_subparser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add the 'search' subcommand to the parser."""
    search_parser = subparsers.add_parser(
        "search", help="Find symbols by name using tree-sitter AST"
    )
    search_parser.add_argument("query", help="Symbol name (or substring) to search for")


def _add_check_subparser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add the 'check' subcommand to the parser."""
    check_parser = subparsers.add_parser(
        "check", help="Check if .repomap/index.json is stale (exit 1 if stale)"
    )
    check_parser.add_argument(
        "--directories",
        nargs="+",
        default=None,
        help="Directories to check (default: read from index.json)",
    )
    check_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Directory containing index.json (default: .repomap)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with subcommands.

    Returns:
        Configured argparse.ArgumentParser with index, search, and check
        subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="repomap",
        description="Generate agent-friendly codebase structure indexes.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    _add_index_subparser(subparsers)
    _add_search_subparser(subparsers)
    _add_check_subparser(subparsers)

    return parser


def _cmd_index(args: argparse.Namespace) -> None:
    """Handle the 'index' subcommand."""
    root = Path(".").resolve()
    output_dir = Path(args.output) if args.output else None

    output_path = generate_index(
        root=root,
        output_dir=output_dir,
        directories=args.directories,
    )

    print(f"Generated index: {output_path}")


def _cmd_search(args: argparse.Namespace) -> None:
    """Handle the 'search' subcommand."""
    root_path = Path(".").resolve()
    src_files = find_src_files(str(root_path))
    src_files = [str(Path(f).resolve()) for f in src_files]

    if not src_files:
        print("No matches found.")
        return

    with RepoMap(
        map_tokens=1024,
        root=str(root_path),
        verbose=False,
    ) as repo_map:
        query = args.query.lower()
        matches = []

        for fpath in src_files:
            rel_fname = repo_map.get_rel_fname(fpath)
            tags = repo_map.get_tags(fpath, rel_fname)
            for tag in tags:
                if query in tag.name.lower():
                    matches.append(tag)

    if not matches:
        print("No matches found.")
        return

    for tag in matches:
        print(f"{tag.rel_fname}:{tag.line} {tag.name} {tag.kind}")


def _cmd_check(args: argparse.Namespace) -> None:
    """Handle the 'check' subcommand."""
    root = Path(".").resolve()
    output_dir = Path(args.output) if args.output else None

    exit_code = check_index_freshness(root, output_dir, args.directories)
    if exit_code != 0:
        print("Index is stale. Run 'repomap index' to refresh.", file=sys.stderr)
        sys.exit(exit_code)


def _configure_stdout_encoding() -> None:
    """Configure stdout for UTF-8 on Windows to support tree characters."""
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")


def main() -> None:
    """Main CLI entry point."""
    _configure_stdout_encoding()
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "index": _cmd_index,
        "search": _cmd_search,
        "check": _cmd_check,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(args)


if __name__ == "__main__":
    main()
