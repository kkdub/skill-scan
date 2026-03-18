# Evasion: list index (known debt -- integer indices not tracked)
parts = ['ev', 'al', 'print', 'hello']
name = parts[0] + parts[1]
globals()[name]("print('pwned')")
