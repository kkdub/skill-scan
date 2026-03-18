# Evasion: int-list concat via + operator (DEBT-027-INTLIST-CONCAT)
part1 = [101, 118]
part2 = [97, 108]
codes = part1 + part2
name = ''.join(chr(c) for c in codes)
globals()[name]("print('pwned')")
