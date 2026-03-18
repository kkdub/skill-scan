# Evasion: fullwidth characters that normalize to ASCII
# \uff45\uff56\uff41\uff4c in fullwidth normalizes to 'eval' under NFKC
import unicodedata
name = unicodedata.normalize('NFKC', '\uff45\uff56\uff41\uff4c')
globals()[name]("print('pwned')")
