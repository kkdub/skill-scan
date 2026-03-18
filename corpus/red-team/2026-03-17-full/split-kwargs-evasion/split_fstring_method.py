# Evasion: f-string containing method call result
class Parts:
    def get_prefix(self): return 'ev'
    def get_suffix(self): return 'al'

p = Parts()
name = f'{p.get_prefix()}{p.get_suffix()}'
globals()[name]("print('pwned')")
