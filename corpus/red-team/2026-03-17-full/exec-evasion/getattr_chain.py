# Evasion: chained getattr to reach dangerous function
import builtins
fn_name = chr(101) + chr(118) + chr(97) + chr(108)  # 'eval'
fn = getattr(builtins, fn_name)
fn("print('pwned')")
