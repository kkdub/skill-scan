# mypy: ignore-errors
# Negative fixture: safe decorators that must NOT trigger EXEC-002/EXEC-006
import functools


@staticmethod
def helper():
    pass


@property
def value(self):
    return 42


def custom_decorator(fn):
    return fn


@custom_decorator
def normal_function():
    pass


def outer():
    @functools.wraps(outer)
    def inner():
        pass

    return inner
