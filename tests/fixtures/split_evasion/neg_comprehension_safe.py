# Comprehension assembly producing non-dangerous string 'hello'
# Should NOT trigger any EXEC-002 or EXEC-006 findings

# ListComp variant
greeting1 = "".join([chr(c) for c in [104, 101, 108, 108, 111]])

# GeneratorExp variant
greeting2 = "".join(chr(c) for c in [104, 101, 108, 108, 111])
