# Positive: chr(ord('x') + 0) padding resistance (R-EFF006) via inline concatenation
_result = (
    chr(ord("e") + 0) + chr(ord("v") + 0) + chr(ord("a") + 0) + chr(ord("l") + 0)
)  # should detect "eval"
