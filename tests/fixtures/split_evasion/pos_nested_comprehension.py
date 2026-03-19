# Positive: nested comprehension with chr() over list-of-lists builds 'eval'
name = "".join(chr(c) for row in [[101, 118], [97, 108]] for c in row)
