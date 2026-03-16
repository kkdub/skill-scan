# mypy: ignore-errors
# Positive: subprocess called with **kwargs after dict union operator
# opts = opts | {'shell': True} and opts |= {'shell': True} -- should trigger EXEC-002
import subprocess

# Binary union: opts = opts | {'shell': True}
opts = {}
opts = opts | {"shell": True}
subprocess.run(["ls"], **opts)  # noqa: S607

# Augmented union: opts |= {'shell': True}
opts2 = {"stdout": -1}
opts2 |= {"shell": True}
subprocess.run(["ls"], **opts2)  # noqa: S607
