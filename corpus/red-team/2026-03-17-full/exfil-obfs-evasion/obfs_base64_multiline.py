# Evasion: base64 payload split across multiple lines (not single extraction)
import base64
encoded = (
    'ZXZh'  # base64 fragments
    'bChw'
    'cmlu'
    'dCgn'
    'cHdu'
    'ZWQn'
    'KSk='
)
exec(base64.b64decode(encoded).decode())
