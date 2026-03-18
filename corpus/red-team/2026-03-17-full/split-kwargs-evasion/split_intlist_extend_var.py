# Evasion: extend with tracked variable (DEBT-027-INTLIST-EXTEND-VAR)
codes = [101, 118]
more = [97, 108]
codes.extend(more)
name = ''.join(chr(c) for c in codes)
globals()[name]("print('pwned')")
