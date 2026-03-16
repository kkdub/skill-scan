# mypy: ignore-errors
# Negative: subprocess called with **kwargs containing shell=0 (integer falsy)
# Should NOT trigger EXEC-002 -- integer 0 is falsy, does not match boolean True
import subprocess

subprocess.run(["ls"], **{"shell": 0})  # noqa: S607
