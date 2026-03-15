# Positive: functools.reduce(lambda a,b: a+b, [...]) builds dangerous name
import functools

# Direct functools.reduce with lambda
_result = functools.reduce(lambda a, b: a + b, ["ev", "al"])

# Aliased functools
import functools as ft  # noqa: E402

_result2 = ft.reduce(lambda a, b: a + b, ["ex", "ec"])
