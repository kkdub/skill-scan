"""Filesystem traversal for skill scanning — I/O only.

Walks a skill directory and gathers raw filesystem metadata into FileEntry
objects. Reports symlink status and resolved paths without determining if
symlinks are internal or external. All classification decisions happen in
file_classifier.py.
"""

from __future__ import annotations

from pathlib import Path

from skill_scan.models import FileEntry


def walk_skill_dir(skill_dir: Path) -> tuple[list[FileEntry], Path]:
    """Walk a skill directory and gather metadata for each file entry.

    Returns:
        (entries, resolved_root) where entries are file metadata objects
        and resolved_root is the fully resolved skill directory path.
    """
    resolved_root = skill_dir.resolve()
    entries: list[FileEntry] = []
    for file_path in sorted(skill_dir.rglob("*")):
        entry = _gather_entry(file_path, skill_dir, resolved_root)
        if entry is not None:
            entries.append(entry)
    return entries, resolved_root


def _gather_entry(
    file_path: Path,
    skill_dir: Path,
    resolved_root: Path,
) -> FileEntry | None:
    """Gather filesystem metadata for a single directory entry.

    Returns None for entries that are not relevant (directories,
    symlinks to directories, stat failures). For symlinks to files,
    reports is_symlink=True and the resolved target path; the classifier
    determines if the symlink is internal or external.
    """
    rel = file_path.relative_to(skill_dir).as_posix()
    resolved = file_path.resolve()
    is_symlink = file_path.is_symlink()

    # Skip directories and symlinks to directories
    if is_symlink:
        if not resolved.is_file():
            return None
        # Return symlink metadata; classifier will determine if external
        try:
            size = file_path.stat().st_size
        except OSError:
            size = 0
        return FileEntry(
            path=file_path,
            relative_path=rel,
            suffix=file_path.suffix,
            size=size,
            is_symlink=True,
            resolved_path=resolved,
        )

    # For regular files, ensure they're within the root (security check)
    if not file_path.is_file() or not resolved.is_relative_to(resolved_root):
        return None

    try:
        size = file_path.stat().st_size
    except OSError:
        size = 0

    return FileEntry(
        path=file_path,
        relative_path=rel,
        suffix=file_path.suffix,
        size=size,
        is_symlink=False,
        resolved_path=resolved,
    )
