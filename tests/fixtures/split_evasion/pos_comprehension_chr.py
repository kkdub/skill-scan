# Comprehension assembly via join with chr() mapping over inline int list
# Both ListComp and GeneratorExp variants building 'eval'

# ListComp variant
name1 = "".join([chr(c) for c in [101, 118, 97, 108]])

# GeneratorExp variant
name2 = "".join(chr(c) for c in [101, 118, 97, 108])
