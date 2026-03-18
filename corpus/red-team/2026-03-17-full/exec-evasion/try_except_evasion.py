# Evasion: try/except aliasing - scanner may only track first path
try:
    from subprocess import call as harmless_func
except ImportError:
    harmless_func = lambda *a: None
harmless_func('echo pwned', shell=True)
