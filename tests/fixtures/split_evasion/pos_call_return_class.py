# Positive: class methods returning fragments, self.method() concat to "popen"
class Exploit:
    def prefix(self) -> str:
        return "po"

    def suffix(self) -> str:
        return "pen"

    def run(self) -> None:
        _cmd = self.prefix() + self.suffix()  # should detect "popen"
