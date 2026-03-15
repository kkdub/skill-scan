# Negative: .replace() chains producing non-dangerous strings

# Simple safe replacement
greeting = "hello".replace("h", "j")  # "jello"

# Multi-step safe replacement
cleaned = "foo_bar_baz".replace("_", "-").replace("baz", "qux")  # "foo-bar-qux"

# Variable base safe replacement
template = "Dear NAME, welcome to PLACE"
msg = template.replace("NAME", "Alice").replace("PLACE", "Wonderland")
