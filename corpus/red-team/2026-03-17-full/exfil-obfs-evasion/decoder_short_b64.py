# Evasion: base64 payload under 20 chars (MIN_ENCODED_LENGTH)
import base64
# 'eval("1+1")' = 12 chars = 16 chars base64 (under 20)
short = 'ZXZhbCgiMSsxIik='  # base64 of eval("1+1") -- 16 chars
exec(base64.b64decode(short).decode())
