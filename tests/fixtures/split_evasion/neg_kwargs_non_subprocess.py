# mypy: ignore-errors
# Negative: dict unpacking into a non-subprocess function
# Should NOT trigger EXEC-002 -- only subprocess calls are dangerous


def safe_function(shell=False, verbose=True):
    return shell, verbose


opts = {"shell": True, "verbose": False}
safe_function(**opts)
