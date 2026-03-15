# mypy: ignore-errors
# Negative: function with **kwargs parameter forwarding
# Should NOT trigger EXEC-002 -- no dangerous kwargs unpacking here


def wrapper(**kwargs):
    """Pass-through kwargs to an inner function."""
    inner(**kwargs)


def inner(**kwargs):
    return kwargs
