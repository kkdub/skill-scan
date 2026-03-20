"""Bulk module rename tool for skill-scan.

Renames source modules in src/skill_scan/ and their test counterparts,
rewriting all import statements across the codebase.

Usage:
    python -m scripts.rename_module              # use built-in RENAME_MAP
    python -m scripts.rename_module mapping.json  # use JSON file
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Full rename mapping — source modules
# ---------------------------------------------------------------------------
RENAME_MAP: dict[str, str] = {
    # Source module renames (skill_scan.*)
    "_ast_helpers": "_ast_imports",
    "_ast_split_helpers": "_ast_split_format",
    "_ast_split_join_helpers": "_ast_split_comprehension",
    "_ast_split_star_helpers": "_ast_split_star_unpack",
    "_ast_split_map_helpers": "_ast_split_map_resolver",
    "_ast_split_int_list_helpers": "_ast_split_int_list_tracker",
    "_ast_symbol_table_helpers": "_ast_symbol_table_assignments",
    "_ast_symbol_table_dict_helpers": "_ast_symbol_table_dict_tracker",
    "_ast_symbol_table_class_helpers": "_ast_symbol_table_self_attrs",
    "_ast_symbol_table_return_helpers": "_ast_symbol_table_returns",
    "_decoder_helpers": "_decoder_base64_hex",
    # Inter-test renames (tests.unit.*)
    "kwargs_test_helpers": "kwargs_test_utils",
    "test_ast_split_helpers": "test_ast_split_format",
}


def rewrite_imports(content: str, rename_map: dict[str, str]) -> str:
    """Rewrite import lines in *content* according to *rename_map*.

    Only rewrites lines that are actual Python import statements
    (``from X import ...`` or ``import X``).  String literals,
    comments, and docstrings are left untouched.

    Handles both ``skill_scan.{old}`` and ``tests.unit.{old}`` patterns.
    """
    lines = content.split("\n")
    result: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith(("from ", "import ")):
            for old, new in rename_map.items():
                # from skill_scan.{old} import ...
                # from skill_scan.{old} (end of line, bare import)
                line = re.sub(
                    rf"(\bfrom\s+skill_scan\.){re.escape(old)}\b",
                    rf"\g<1>{new}",
                    line,
                )
                # import skill_scan.{old}
                line = re.sub(
                    rf"(\bimport\s+skill_scan\.){re.escape(old)}\b",
                    rf"\g<1>{new}",
                    line,
                )
                # from tests.unit.{old} import ...
                line = re.sub(
                    rf"(\bfrom\s+tests\.unit\.){re.escape(old)}\b",
                    rf"\g<1>{new}",
                    line,
                )
                # import tests.unit.{old}
                line = re.sub(
                    rf"(\bimport\s+tests\.unit\.){re.escape(old)}\b",
                    rf"\g<1>{new}",
                    line,
                )
        result.append(line)
    return "\n".join(result)


def map_test_file(old_module: str, new_module: str) -> tuple[str, str]:
    """Map a source module rename to the corresponding test file rename.

    Strips leading underscore from both names and prepends ``test_``.
    Returns ``(old_test_filename, new_test_filename)``.
    """
    old_stem = old_module.lstrip("_")
    new_stem = new_module.lstrip("_")
    return (f"test_{old_stem}.py", f"test_{new_stem}.py")


# ---------------------------------------------------------------------------
# Git + filesystem operations (not tested by unit tests)
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src" / "skill_scan"
_TESTS = _ROOT / "tests" / "unit"


def _git_mv(src: Path, dst: Path) -> None:
    """Run git mv, skip if src doesn't exist or dst already exists."""
    if not src.exists():
        print(f"  SKIP (not found): {src.name}")
        return
    if dst.exists():
        print(f"  SKIP (already exists): {dst.name}")
        return
    subprocess.run(
        ["git", "mv", str(src), str(dst)],
        check=True,
        cwd=str(_ROOT),
    )
    print(f"  git mv {src.name} -> {dst.name}")


def _rewrite_file(path: Path, rename_map: dict[str, str]) -> bool:
    """Rewrite imports in a single file.  Returns True if changed."""
    text = path.read_text(encoding="utf-8")
    new_text = rewrite_imports(text, rename_map)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def _collect_python_files() -> list[Path]:
    """Collect all .py files under src/ and tests/."""
    files: list[Path] = []
    for d in (_ROOT / "src", _ROOT / "tests"):
        files.extend(d.rglob("*.py"))
    return files


def _is_test_only(name: str) -> bool:
    """Return True if *name* is a test-only rename (not a source module)."""
    return name.startswith("test_") or name == "kwargs_test_helpers"


def _split_rename_map(rmap: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """Split *rmap* into (src_renames, test_only_renames)."""
    src = {k: v for k, v in rmap.items() if not _is_test_only(k)}
    test_only = {k: v for k, v in rmap.items() if _is_test_only(k)}
    return src, test_only


def _rename_src_modules(src_renames: dict[str, str]) -> None:
    """git mv source module files and their test counterparts."""
    print("=== Renaming source modules ===")
    for old_n, new_n in src_renames.items():
        _git_mv(_SRC / f"{old_n}.py", _SRC / f"{new_n}.py")
    print("=== Renaming test files (source module counterparts) ===")
    for old_n, new_n in src_renames.items():
        old_test, new_test = map_test_file(old_n, new_n)
        _git_mv(_TESTS / old_test, _TESTS / new_test)


def _rename_test_only(test_only_renames: dict[str, str]) -> None:
    """git mv test-only files."""
    print("=== Renaming test-only files ===")
    for old_n, new_n in test_only_renames.items():
        _git_mv(_TESTS / f"{old_n}.py", _TESTS / f"{new_n}.py")


def _rewrite_all_imports(rmap: dict[str, str]) -> None:
    """Rewrite imports in every Python file under src/ and tests/."""
    print("=== Rewriting imports ===")
    changed = 0
    for path in _collect_python_files():
        if _rewrite_file(path, rmap):
            print(f"  REWRITTEN: {path.relative_to(_ROOT)}")
            changed += 1
    print(f"{changed} files rewritten")


def run(rename_map: dict[str, str] | None = None) -> None:
    """Execute the full rename: git mv + import rewriting."""
    rmap = rename_map or RENAME_MAP
    src_renames, test_only_renames = _split_rename_map(rmap)
    _rename_src_modules(src_renames)
    _rename_test_only(test_only_renames)
    _rewrite_all_imports(rmap)


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) > 1:
        mapping_file = Path(sys.argv[1])
        with mapping_file.open() as f:
            rmap = json.load(f)
        run(rmap)
    else:
        run()


if __name__ == "__main__":
    main()
