# Positive: .replace() chain building dangerous names

# 2-step replace chain building "eval"
name_two = "eXYl".replace("X", "va").replace("Y", "")

# 3+ step replace chain building "exec"
name_three = "abbc".replace("a", "e").replace("bb", "xe").replace("c", "c")

# Tracked variable base building "system"
base = "syZZem"
name_var = base.replace("ZZ", "st")
