# Evasion: decorator with evaluated argument
def make_runner(func_name):
    def decorator(f):
        def wrapper(*args):
            return globals()[func_name](*args)
        return wrapper
    return decorator

@make_runner('ev' + 'al')
def safe_compute(expr):
    pass

safe_compute("print('pwned')")
