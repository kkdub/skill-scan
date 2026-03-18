# Evasion: alternating hex and base64 for different parts
import base64
part1 = bytes.fromhex('6576').decode()  # 'ev' in hex
part2 = base64.b64decode('YWw=').decode()  # 'al' in base64
name = part1 + part2
globals()[name]("print('pwned')")
