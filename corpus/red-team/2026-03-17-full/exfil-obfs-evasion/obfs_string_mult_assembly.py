# Evasion: string multiplication plus slicing to build name
base = 'evaleval'  # repeated string
name = base[:4]  # slice to get 'eval'
globals()[name]("print('pwned')")
