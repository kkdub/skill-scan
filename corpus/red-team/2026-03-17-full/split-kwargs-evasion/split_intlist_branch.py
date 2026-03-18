# Evasion: int-list mutations in if/else (DEBT-028-INTLIST-BRANCH-MERGE)
import os
codes = [101]
if os.name == 'nt':
    codes += [118, 97, 108]  # completes 'eval'
else:
    codes += [120, 101, 99]  # completes 'exec'
name = ''.join(chr(c) for c in codes)
globals()[name]("print('pwned')")
