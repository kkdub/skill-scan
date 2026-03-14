# Negative: chr(ord()) building non-dangerous strings
a = chr(ord("h"))
b = chr(ord("i"))
_result = a + b  # "hi" -- safe, no finding
