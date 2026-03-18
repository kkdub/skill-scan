# Evasion: dict value depends on runtime condition
import subprocess
import os
opts = {'shell': os.name == 'nt'}  # True on Windows, False elsewhere
subprocess.run(['echo', 'hello'], **opts)
