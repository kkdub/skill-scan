# Red-team: Multiple += chains building up a dangerous name
# Target: _collect_int_list_assigns / _extend_tracked
# Expected: EXEC-002 detection

# --- Pattern 1: Long += chain, one int at a time ---
codes = [101]
codes += [118]
codes += [97]
codes += [108]
x = ''.join(chr(c) for c in codes)

# --- Pattern 2: += chain in function scope ---
def chain_func():
    c = [101]
    c += [120]
    c += [101]
    c += [99]
    x = ''.join(chr(i) for i in c)

# --- Pattern 3: Alternating += with different variable names ---
a = [101, 118]
b = [97, 108]
# This should NOT detect since 'codes' is built from a + b (BinOp), not +=
codes = a + b
x = ''.join(chr(c) for c in codes)

# --- Pattern 4: += with tuple RHS ---
codes2 = [101]
codes2 += (118, 97, 108)
x2 = ''.join(chr(c) for c in codes2)

# --- Pattern 5: Five-step += chain ---
def five_step():
    data = []
    data += [95]   # _
    data += [95]   # _
    data += [105]  # i
    data += [109]  # m
    data += [112]  # p
    data += [111]  # o
    data += [114]  # r
    data += [116]  # t
    data += [95]   # _
    data += [95]   # _
    x = ''.join(chr(c) for c in data)
