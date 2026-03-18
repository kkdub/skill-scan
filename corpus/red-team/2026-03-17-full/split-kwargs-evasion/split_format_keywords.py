# Evasion: format with keyword args (only positional tracked)
name = '{prefix}{suffix}'.format(prefix='ev', suffix='al')
globals()[name]("print('pwned')")
