# mypy: ignore-errors
# Positive: subprocess imported under alias, called with **kwargs unpacking
# containing shell=True -- should trigger EXEC-002
import subprocess as sp

sp.run(["ls"], **{"shell": True})  # noqa: S607
