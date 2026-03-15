# mypy: ignore-errors
# Negative: operator.add/concat with safe (non-dangerous) results
import functools
import operator

# Safe string via operator.add
_greeting = functools.reduce(operator.add, ["hel", "lo"])  # codespell:ignore hel

# Safe string via operator.concat
_welcome = functools.reduce(operator.concat, ["wel", "come"])  # codespell:ignore wel
