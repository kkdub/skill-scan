# Evasion: dict.pop() not tracked
funcs = {'target': 'eval', 'decoy': 'print'}
name = funcs.pop('target')
globals()[name]("print('pwned')")
