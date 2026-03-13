# Dict literal evasion: parts = {'a': 'ev', 'b': 'al'}; eval via subscript concat
parts = {"a": "ev", "b": "al"}
result = parts["a"] + parts["b"]
