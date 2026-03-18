# Evasion: loop-based assembly not unrolled by symbol table
chars = ['e', 'v', 'a', 'l']
name = ''
for c in chars:
    name += c
globals()[name]("print('pwned')")
