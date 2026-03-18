# Evasion: multiple targets in assignment (a = b = 'val')
a = b = 'eval'
globals()[a]("print('pwned')")
