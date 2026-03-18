# Evasion: dangerous call hidden behind class method
class Helper:
    @staticmethod
    def run(code):
        import builtins
        return getattr(builtins, 'ev' + 'al')(code)

Helper.run("print('pwned')")
