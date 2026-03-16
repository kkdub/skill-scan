# mypy: ignore-errors
# Negative: dict union with unresolvable operand -- should NOT trigger EXEC-002
# Conservative: when either operand cannot be resolved, skip entirely
import subprocess

# Unresolvable left operand (unknown variable)
opts = unknown | {"shell": True}  # noqa: F821
subprocess.run(["ls"], **opts)  # noqa: S607

# PEP 448 spread dict -- already handled as unresolvable
subprocess.run(["ls"], **{**base, "shell": True})  # noqa: S607, F821
