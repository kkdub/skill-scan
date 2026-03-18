# Evasion: nested dict subscript (only single-level tracked)
config = {'funcs': {'target': 'eval'}}
name = config['funcs']['target']
globals()[name]("print('pwned')")
