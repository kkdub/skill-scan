# Negative: reversed() on safe strings, no dangerous name
_safe1 = "".join(reversed("olleh"))  # "hello" -- safe
_safe2 = "".join(reversed(["d", "l", "r", "o", "w"]))  # "world" -- safe
