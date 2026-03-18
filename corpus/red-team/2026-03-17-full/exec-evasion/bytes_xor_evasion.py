# Evasion: XOR bytes to produce dangerous string
key = 0xFF
encoded = [0x9A, 0x89, 0x9E, 0x93]  # 'eval' XORed with 0xFF
name = ''.join(chr(b ^ key) for b in encoded)
globals()[name]("print('pwned')")
