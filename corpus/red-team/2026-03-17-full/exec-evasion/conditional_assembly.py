# Evasion: conditional branches merge differently in symbol table
import os
x = 'harm'
if os.name == 'nt':
    x = 'ev'
    y = 'al'
else:
    x = 'ex'
    y = 'ec'
result = x + y
globals()[result]("print('pwned')")
