"""Tests for file_collector — filesystem traversal and metadata gathering."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from skill_scan.file_collector import walk_skill_dir


class TestGatherEntryStatFailure:
    """Verify that stat() failures produce entries with size=0, not skips.

    A security scanner must not silently drop files it cannot stat,
    since a TOCTOU race could otherwise let a malicious skill evade
    scanning. Instead, files that fail stat() are included with size=0
    and proceed to content scanning, where OSError is handled gracefully.
    """

    def test_regular_file_stat_oserror_included_with_zero_size(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()
        target = skill_dir / "script.py"
        target.write_text("print('hi')", encoding="utf-8")

        original_stat = Path.stat
        # Track calls per path so is_symlink() and is_file() succeed
        # but the explicit stat() call for size fails.
        call_counts: dict[str, int] = {}

        def failing_stat(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
            if self.name == "script.py":
                key = str(self)
                call_counts[key] = call_counts.get(key, 0) + 1
                # 1st: is_symlink (lstat), 2nd: is_file — let pass
                # 3rd: explicit stat() for size — fail
                if call_counts[key] >= 3:
                    raise OSError("Permission denied")
            return original_stat(self, *args, **kwargs)

        with patch.object(Path, "stat", failing_stat):
            entries, _ = walk_skill_dir(skill_dir)

        assert len(entries) == 1
        assert entries[0].relative_path == "script.py"
        assert entries[0].size == 0
        assert entries[0].is_symlink is False
