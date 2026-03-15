# mypy: ignore-errors
# Positive fixture: decorator evasion using dangerous names as decorators
# Each decorator usage is an evasion technique -- no body-level calls.


@eval  # noqa: S307
def encoded_payload():
    pass


@exec
def run_code():
    pass


import builtins  # noqa: E402


@builtins.eval
class Exploit:
    pass
