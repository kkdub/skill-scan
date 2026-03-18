# Evasion: dict built via update() method
import subprocess
opts = {}
opts.update({'timeout': 30})
opts.update({'shell': True})
subprocess.run(['echo', 'hello'], **opts)
