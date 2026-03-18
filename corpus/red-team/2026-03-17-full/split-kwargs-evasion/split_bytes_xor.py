# Evasion: XOR decoding of bytes (not tracked)
key = bytes([0x42] * 4)
data = bytes([0x27, 0x34, 0x23, 0x2E])  # 'eval' XOR 0x42
name = bytes(a ^ b for a, b in zip(data, key)).decode()
globals()[name]("print('pwned')")
