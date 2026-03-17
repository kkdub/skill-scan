# Red-team: Mixed mutation sequences (assign then +=, then .extend())
# Target: _handle_int_list_stmt dispatch across statement types
# Expected: EXEC-002 detection

# --- Pattern 1: Assign + += + .extend() chain ---
codes = [101]
codes += [118]
codes.extend([97, 108])
x = ''.join(chr(c) for c in codes)

# --- Pattern 2: Assign then extend then += ---
def mixed_order():
    data = [101, 118]
    data.extend([97])
    data += [108]
    x = ''.join(chr(c) for c in data)

# --- Pattern 3: Reassign then += (should use new value) ---
codes2 = [1, 2, 3]  # safe initial
codes2 = [101, 118]  # reassigned to dangerous prefix
codes2 += [97, 108]  # completes dangerous name
x2 = ''.join(chr(c) for c in codes2)

# --- Pattern 4: += then reassign (should use reassigned value) ---
codes3 = [101, 118]
codes3 += [97, 108]  # dangerous
codes3 = [104, 105]  # reassigned to safe -- should override
x3 = ''.join(chr(c) for c in codes3)  # should NOT detect

# --- Pattern 5: Shadow after mutation ---
def shadow_after_mutation():
    codes = [101, 118]
    codes += [97, 108]
    codes = "hello"  # reassigned to non-list
    x = ''.join(chr(c) for c in codes)  # should NOT detect -- shadowed

# --- Pattern 6: Multiple variables, interleaved mutations ---
def interleaved():
    a = [101]
    b = [115, 121]
    a += [118]
    b.extend([115, 116])
    a.extend([97, 108])
    b += [101, 109]
    xa = ''.join(chr(c) for c in a)
    xb = ''.join(chr(c) for c in b)
