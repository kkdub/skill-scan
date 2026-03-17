# Red-team: AugAssign with Tuple not List (tuple RHS)
# Target: _extend_tracked handling of ast.Tuple
# Expected: EXEC-002 detection

# --- Pattern 1: Simple tuple RHS ---
codes = [101, 118]
codes += (97, 108)
x = ''.join(chr(c) for c in codes)

# --- Pattern 2: All-tuple chain ---
codes2 = [101]
codes2 += (118,)
codes2 += (97,)
codes2 += (108,)
x2 = ''.join(chr(c) for c in codes2)

# --- Pattern 3: .extend() with tuple arg ---
codes3 = [101, 118]
codes3.extend((97, 108))
x3 = ''.join(chr(c) for c in codes3)

# --- Pattern 4: Mixed list and tuple in chain ---
def mixed_list_tuple():
    data = [101]
    data += [118]       # list
    data += (97,)       # tuple
    data.extend([108])  # list via extend
    x = ''.join(chr(c) for c in data)
