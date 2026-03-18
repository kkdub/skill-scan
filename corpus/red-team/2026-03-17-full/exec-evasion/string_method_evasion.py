# Evasion: string methods other than replace not resolved
name = 'EVAL'.lower()
globals()[name]("print('pwned')")
