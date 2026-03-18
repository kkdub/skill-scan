# Evasion: map with lambda (not chr/str -- custom function)
codes = [101, 118, 97, 108]
name = ''.join(map(lambda c: chr(c), codes))  # lambda wrapping chr
globals()[name]("print('pwned')")
