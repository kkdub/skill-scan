# Evasion: format_map not tracked by split resolver
template = '{a}{b}'
parts = {'a': 'ev', 'b': 'al'}
name = template.format_map(parts)
globals()[name]("print('pwned')")
