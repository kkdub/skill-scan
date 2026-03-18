# Evasion: 3 levels deep (decoder max is 2)
import base64
# base64(base64(base64("eval(malicious_code)")))
payload = 'WlhaaGJDaHRZV3hwWTJsdmRYTmZZMjlrWlNrPQ=='  # 3x base64 of "eval(malicious_code)"
decoded = base64.b64decode(base64.b64decode(base64.b64decode(payload)))
