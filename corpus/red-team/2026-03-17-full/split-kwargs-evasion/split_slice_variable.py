# Evasion: slice bounds are variables, not constants
s = 'xxxevalxxx'
start = 3
end = 7
name = s[start:end]
globals()[name]("print('pwned')")
