# Positive: string concatenation building dangerous names via symbol table
# BinOp concat splits dangerous names across variables; the symbol table
# tracks each variable's value and the split detector reconstructs the full name.

# Two-part BinOp concat building 'eval'
prefix = "eva"
suffix = "l"
result = prefix + suffix

# Direct assignment of 'exec' (baseline: symbol table tracks it)
cmd2 = "exec"

# Three-part concat building 'system' (R-EFF003)
part = "system"
cmd = part + ""
