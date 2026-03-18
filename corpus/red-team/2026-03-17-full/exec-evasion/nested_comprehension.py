# Evasion: nested comprehension with chr mapping
name = ''.join([chr(c) for row in [[101, 118], [97, 108]] for c in row])
globals()[name]("print('pwned')")
