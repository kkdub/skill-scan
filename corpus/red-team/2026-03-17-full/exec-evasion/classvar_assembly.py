# Evasion: class-level variable assembly (class scope not fully tracked)
class Config:
    prefix = 'ev'
    suffix = 'al'
    func_name = prefix + suffix

globals()[Config.func_name]("print('pwned')")
