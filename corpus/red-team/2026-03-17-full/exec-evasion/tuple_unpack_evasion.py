# Evasion: tuple unpacking for assignment
(a, b) = ('ev', 'al')
globals()[a + b]("print('pwned')")
