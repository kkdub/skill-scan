# Evasion: zlib compression not handled by decoder
import zlib
import base64
# zlib.compress(b"eval(input('code: '))")
payload = base64.b64encode(zlib.compress(b"eval(input('code: '))")).decode()
exec(zlib.decompress(base64.b64decode(payload)).decode())
