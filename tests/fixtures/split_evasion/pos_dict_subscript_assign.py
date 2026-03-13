# Dict subscript assignment evasion: d['a'] = 'ev'; d['b'] = 'al'; eval(...)
d = {}
d["a"] = "ev"
d["b"] = "al"
result = d["a"] + d["b"]
