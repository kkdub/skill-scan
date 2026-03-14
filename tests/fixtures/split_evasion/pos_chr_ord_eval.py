# Positive: chr(ord('x')) nesting reconstructs "eval" via inline concatenation
_result = chr(ord("e")) + chr(ord("v")) + chr(ord("a")) + chr(ord("l"))  # should detect "eval"
