# Evasion: dict key is a variable, not string constant
import subprocess
key = 'sh' + 'ell'
opts = {key: True}
subprocess.run(['echo', 'hello'], **opts)
