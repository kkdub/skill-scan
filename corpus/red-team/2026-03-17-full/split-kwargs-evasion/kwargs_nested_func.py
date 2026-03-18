# Evasion: dict built and returned from a function
import subprocess

def get_opts():
    return {'shell': True, 'timeout': 30}

subprocess.run(['echo', 'hello'], **get_opts())
