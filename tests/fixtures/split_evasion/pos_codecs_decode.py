# Positive: codecs.decode(b'...', encoding) resolves to dangerous name
import codecs

_result = codecs.decode(b"system", "utf-8")
