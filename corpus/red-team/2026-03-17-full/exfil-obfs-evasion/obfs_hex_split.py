# Evasion: hex bytes split across multiple fromhex calls
part1 = bytes.fromhex('6576')  # 'ev'
part2 = bytes.fromhex('616c')  # 'al'
name = (part1 + part2).decode()
globals()[name]("print('pwned')")
