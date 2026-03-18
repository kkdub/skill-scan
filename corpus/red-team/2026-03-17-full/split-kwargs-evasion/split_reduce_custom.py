# Evasion: reduce with a named function instead of lambda/operator.add
from functools import reduce

def combine(a, b):
    return a + b

name = reduce(combine, ['ev', 'al'])
globals()[name]("print('pwned')")
