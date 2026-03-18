# Evasion: multi-level indirection that exceeds symbol table tracking
def get_func_name():
    parts = {}
    parts['a'] = 'ev'
    parts['b'] = 'al'
    return parts['a'] + parts['b']

name = get_func_name()
# Call via globals with computed name
globals()[name]("print('pwned')")
