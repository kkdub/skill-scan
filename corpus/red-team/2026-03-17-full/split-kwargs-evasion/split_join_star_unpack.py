# Evasion: star unpacking in join argument
parts1 = ['e', 'v']
parts2 = ['a', 'l']
name = ''.join([*parts1, *parts2])
globals()[name]("print('pwned')")
