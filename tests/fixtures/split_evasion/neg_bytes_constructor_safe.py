# Negative: bytes constructors with non-dangerous content should not trigger
import codecs

safe1 = bytearray(b"hello").decode()
safe2 = str(b"world", "utf-8")
safe3 = codecs.decode(b"greeting", "utf-8")
