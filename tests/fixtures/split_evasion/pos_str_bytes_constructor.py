# Positive: str(b'...', encoding) resolves to dangerous name
_result = str(b"exec", "utf-8")
