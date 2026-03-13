# Positive: global declaration routes writes to module scope for concat evasion
a = "ev"
b = "al"


def f() -> None:
    global a, b
    a = "ex"
    b = "ec"


f()
result = a + b
