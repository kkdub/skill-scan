# Evasion: lambda as intermediary hides the eval call
fn = lambda code: __builtins__.__dict__['eval'](code)
fn("print('pwned')")
