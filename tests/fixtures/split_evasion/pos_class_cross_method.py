# Positive: cross-method evasion -- self.x in one method, self.y in another, concat in third
class Evasion:
    def build(self) -> None:
        self.x = "ev"

    def setup(self) -> None:
        self.y = "al"

    def run(self) -> None:
        _result = self.x + self.y
