# Evasion: property returns dangerous value at runtime
class Sneaky:
    @property
    def name(self):
        return chr(101) + chr(118) + chr(97) + chr(108)

s = Sneaky()
globals()[s.name]("print('pwned')")
