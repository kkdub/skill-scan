# Positive: bytearray(b'...').decode() resolves to dangerous name
_result = bytearray(b"eval").decode()
