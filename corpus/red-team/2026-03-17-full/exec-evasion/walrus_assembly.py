# Evasion: walrus operator assigns during condition check
import re
if (m := 'ev') and (n := 'al'):
    globals()[m + n]("print('pwned')")
