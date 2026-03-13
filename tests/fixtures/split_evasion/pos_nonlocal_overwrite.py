# Positive: nonlocal declaration overwrites enclosing scope with dangerous name


def outer() -> None:
    a = "ev"
    b = "al"

    def inner() -> None:
        nonlocal a
        a = "ex"
        nonlocal b
        b = "ec"

    inner()
    _result = a + b
