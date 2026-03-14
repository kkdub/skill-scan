# Positive: reversed() inside join reconstructs dangerous names

# reversed string literal
_r1 = "".join(reversed("lave"))  # should detect "eval"

# reversed list of characters
_r2 = "".join(reversed(["l", "a", "v", "e"]))  # should detect "eval"
