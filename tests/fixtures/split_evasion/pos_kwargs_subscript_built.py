# mypy: ignore-errors
# Positive: subprocess called with **kwargs unpacking of a dict built via
# subscript assignments -- should trigger EXEC-002
import subprocess

opts = {}
opts["shell"] = True
subprocess.run(["ls"], **opts)  # noqa: S607
