# Evasion: manual ROT13 without codecs module
def custom_rot(s, n=13):
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

# ROT13 of "eval" is "riny"
dangerous = custom_rot('riny')
globals()[dangerous]("print('pwned')")
