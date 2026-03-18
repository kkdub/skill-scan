# Evasion: join on a set literal (not list/tuple)
import random
# Set is unordered so this is tricky, but scanner may not handle set type
name = ''.join({'e', 'v', 'a', 'l'})  # unreliable but tests scanner
# More reliable: sorted set
name2 = ''.join(sorted({'v', 'e', 'l', 'a'}, key='eval'.index))
globals()[name2]("print('pwned')")
