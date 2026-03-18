# Evasion: generator with conditional and transformation
mapping = {1: 'e', 2: 'v', 3: 'a', 4: 'l'}
name = ''.join(mapping[k] for k in sorted(mapping.keys()))
globals()[name]("print('pwned')")
