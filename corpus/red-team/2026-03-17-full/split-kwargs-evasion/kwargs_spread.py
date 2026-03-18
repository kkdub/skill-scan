# Evasion: spread dict (known unresolvable)
import subprocess
base = {'timeout': 30}
subprocess.run(['echo', 'hello'], **{**base, 'shell': True})
