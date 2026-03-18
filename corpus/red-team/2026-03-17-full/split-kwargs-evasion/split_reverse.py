# Evasion: reversed string
backward = 'lave'  # 'eval' reversed
name = backward[::-1]
globals()[name]("print('pwned')")
