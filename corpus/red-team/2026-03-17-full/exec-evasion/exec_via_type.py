# Evasion: using type() to create a class that executes code
code = compile("print('pwned')", "<string>", "exec")
exec_fn = type('Runner', (), {'__init__': lambda self: exec(code)})
exec_fn()
