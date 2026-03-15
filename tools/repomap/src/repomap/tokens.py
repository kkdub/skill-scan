"""
Token counting utilities for RepoMap.

Provides default token counter using tiktoken (optional dependency)
with fallback to character-based approximation.
"""

from collections.abc import Callable


def default_token_counter(text: str) -> int:
    """Count tokens using tiktoken (optional dependency).

    Falls back to rough character-based approximation if tiktoken
    is not installed.

    Args:
        text: The text to count tokens for.

    Returns:
        Estimated token count.
    """
    if not text:
        return 0
    try:
        import tiktoken

        encoding = tiktoken.get_encoding("cl100k_base")
        return len(encoding.encode(text))
    except ImportError:
        # Rough approximation: ~4 chars per token
        return len(text) // 4


def sampled_token_count(
    text: str,
    token_counter: Callable[[str], int],
) -> int:
    """Count tokens with sampling optimisation for long texts.

    For short texts (< 200 chars), counts directly.
    For longer texts, samples ~1% of lines and extrapolates.

    Args:
        text: The text to count tokens for.
        token_counter: Callable that counts tokens in a string.

    Returns:
        Estimated token count.
    """
    if not text:
        return 0

    len_text = len(text)
    if len_text < 200:
        return token_counter(text)

    lines = text.splitlines(keepends=True)
    num_lines = len(lines)

    step = max(1, num_lines // 100)
    sampled_lines = lines[::step]
    sample_text = "".join(sampled_lines)

    if not sample_text:
        return token_counter(text)

    sample_tokens = token_counter(sample_text)

    est_tokens = (sample_tokens / len(sample_text)) * len_text
    return int(est_tokens)
