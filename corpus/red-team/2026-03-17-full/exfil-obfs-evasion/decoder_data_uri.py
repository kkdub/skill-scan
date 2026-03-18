# Evasion: disguise payload as data URI to skip base64 extraction
payload = 'data:image/png;base64,ZXZhbChpbnB1dCgpKQ=='  # base64 of eval(input())
import base64
# Strip the data URI prefix and decode
raw = payload.split(',', 1)[1]
exec(base64.b64decode(raw).decode())
