# mypy: ignore-errors
# Positive: reduce(operator.add/concat, [...]) builds dangerous name
import functools
import operator

# reduce with operator.add
_result = functools.reduce(operator.add, ["ev", "al"])

# reduce with operator.concat
_result2 = functools.reduce(operator.concat, ["ex", "ec"])

# Aliased operator
import operator as op  # noqa: E402

_result3 = functools.reduce(op.add, ["sy", "stem"])
