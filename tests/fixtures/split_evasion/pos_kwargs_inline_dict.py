# mypy: ignore-errors
# Positive: subprocess called with **kwargs unpacking of a pre-assigned dict
# literal variable -- should trigger EXEC-002
import subprocess

opts = {"shell": True}
subprocess.run(["ls"], **opts)  # noqa: S607
