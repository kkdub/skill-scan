# mypy: ignore-errors
# Negative: subprocess called with **kwargs but dict has no dangerous keys
# Should NOT trigger EXEC-002 -- only safe kwargs like stdout/stderr
import subprocess

opts = {"stdout": -1, "stderr": -1}
subprocess.run(["ls"], **opts)  # noqa: S607
