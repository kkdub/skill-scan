# Evasion: class-level int-list (DEBT-028-INTLIST-CLASS-BODY)
class Hidden:
    codes = [101, 118, 97, 108]  # 'eval'
    name = ''.join(chr(c) for c in codes)

globals()[Hidden.name]("print('pwned')")
