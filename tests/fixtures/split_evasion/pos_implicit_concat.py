# Positive: implicit string concatenation (adjacent literals) feeding split evasion
# Python's parser joins adjacent string literals at parse time: 'ev' 'a' -> 'eva'
# Combined with variable concatenation, the split detector reconstructs 'eval'.

# Implicit concat in variable assignment, then BinOp split
prefix = "eva"  # parser merges to 'eva'
suffix = "l"
result = prefix + suffix  # split detector: 'eva' + 'l' = 'eval'

# Three-part implicit concat feeding BinOp split for 'popen'
part1 = "po"  # originally adjacent literals: 'po' 'p' (parser merges)
part2 = "pen"
cmd = part1 + part2  # split detector: 'po' + 'pen' = 'popen'
