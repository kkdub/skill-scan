# Evasion: dict is a class attribute
import subprocess

class Config:
    run_opts = {'shell': True}

subprocess.run(['echo', 'hello'], **Config.run_opts)
