"""Context-aware checking for antipattern detection.

Provides utilities for determining if code is inside specific block structures,
such as try/except blocks with appropriate exception handling.
"""

from __future__ import annotations


def get_indentation(line: str) -> int:
    """Get the indentation level (number of leading spaces) of a line."""
    return len(line) - len(line.lstrip())


def _is_skippable_line(stripped: str) -> bool:
    """Check if a line should be skipped (empty or comment)."""
    return not stripped or stripped.startswith("#")


def _find_enclosing_try_block(
    lines: list[str],
    target_idx: int,
    target_indent: int,
) -> tuple[int, int]:
    """Search backwards from target to find enclosing try block.

    Handles nested control structures by continuing to search at progressively
    lower indentation levels.

    Returns:
        Tuple of (try_idx, try_indent) or (-1, -1) if not found.
    """
    current_indent = target_indent

    for i in range(target_idx - 1, -1, -1):
        line = lines[i]
        stripped = line.strip()

        if _is_skippable_line(stripped):
            continue

        line_indent = get_indentation(line)

        # Only interested in lines at lower indentation than current scope
        if line_indent >= current_indent:
            continue

        # Found a line at lower indentation - check what it is
        if stripped.startswith("try:"):
            return (i, line_indent)

        # Scope boundaries - definitely not inside a try block
        if stripped.startswith(("except", "finally:", "else:", "def ", "async def ", "class ")):
            return (-1, -1)

        # Control structures - continue searching at lower indentation
        current_indent = line_indent

    return (-1, -1)


def _except_handles_type(except_line: str, exception_type: str | None) -> bool:
    """Check if an except clause handles the given exception type."""
    if exception_type is None:
        return True

    # Check for specific exception type (with or without module prefix)
    if exception_type in except_line or f".{exception_type}" in except_line:
        return True

    # Accept broad exception handlers (bare except or except Exception)
    return "except Exception" in except_line or except_line.startswith("except:")


def _is_past_try_block_boundary(
    line_indent: int,
    try_indent: int,
    stripped_line: str,
    current_idx: int,
    target_idx: int,
) -> bool:
    """Check if we've moved past the try/except block structure."""
    is_block_continuation = stripped_line.startswith(("except", "finally:", "else:"))
    is_at_or_below_try_indent = line_indent <= try_indent
    is_after_target = current_idx > target_idx

    return is_at_or_below_try_indent and not is_block_continuation and is_after_target


def _has_matching_except_handler(
    lines: list[str],
    try_idx: int,
    try_indent: int,
    target_idx: int,
    exception_type: str | None,
) -> bool:
    """Search forward from try block for matching except handlers."""
    for i in range(try_idx + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()

        if _is_skippable_line(stripped):
            continue

        line_indent = get_indentation(line)

        # Check for except at try's indentation level
        is_except_at_try_level = line_indent == try_indent and stripped.startswith("except")
        if is_except_at_try_level and _except_handles_type(stripped, exception_type):
            return True

        # Stop if we've moved past the try/except block structure
        if _is_past_try_block_boundary(line_indent, try_indent, stripped, i, target_idx):
            break

    return False


def is_in_try_except_block(
    lines: list[str],
    target_line_num: int,
    exception_type: str | None = None,
) -> bool:
    """Check if a line is inside a try block with appropriate exception handling.

    Args:
        lines: All lines in the file.
        target_line_num: 1-indexed line number to check.
        exception_type: Optional exception type to look for (e.g., "JSONDecodeError").

    Returns:
        True if the line is inside a try block with matching except handler.
    """
    if target_line_num < 1 or target_line_num > len(lines):
        return False

    target_idx = target_line_num - 1
    target_line = lines[target_idx]
    target_indent = get_indentation(target_line)

    try_idx, try_indent = _find_enclosing_try_block(lines, target_idx, target_indent)
    if try_idx == -1:
        return False

    return _has_matching_except_handler(lines, try_idx, try_indent, target_idx, exception_type)
