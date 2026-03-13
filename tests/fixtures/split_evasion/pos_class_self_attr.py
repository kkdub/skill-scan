# Positive: self.attr used in f-string assembly building 'eval'
class Cmd:
    def __init__(self) -> None:
        self.cmd = "eval"

    def run(self) -> None:
        _name = f"{self.cmd}"
