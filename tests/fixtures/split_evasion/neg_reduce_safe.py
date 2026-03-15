# Negative: reduce with safe (non-dangerous) string results
import functools

# Safe string concatenation
_greeting = functools.reduce(lambda a, b: a + b, ["hel", "lo"])  # codespell:ignore hel

# Safe numeric reduce
_total = functools.reduce(lambda a, b: a + b, [1, 2, 3])
