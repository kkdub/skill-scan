# Positive: bytes.fromhex() fragment concatenation + .decode() builds 'eval'
name = (bytes.fromhex("6576") + bytes.fromhex("616c")).decode()
