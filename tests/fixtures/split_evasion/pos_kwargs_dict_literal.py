# mypy: ignore-errors
# Positive: subprocess called with **kwargs unpacking of inline dict literal
# containing shell=True -- should trigger EXEC-002
import subprocess

subprocess.run(["ls"], **{"shell": True})  # noqa: S607
