# mypy: ignore-errors
# Positive: subprocess called with **kwargs containing shell=1 (integer truthy)
# Should trigger EXEC-002 -- integer 1 is truthy, matching boolean True table entry
import subprocess

subprocess.run(["ls"], **{"shell": 1})  # noqa: S607
