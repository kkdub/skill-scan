# Red-team: .extend() with generator arg (out of scope for resolution)
# Target: confirms no crash, not expected to resolve
# Expected: NO crash; detection is NOT required

# --- Pattern 1: Generator expression arg ---
codes = [101, 118]
codes.extend(x for x in [97, 108])
x = ''.join(chr(c) for c in codes)

# --- Pattern 2: range() generator arg ---
codes2 = [101, 118]
codes2.extend(range(97, 99))  # 97, 98
x2 = ''.join(chr(c) for c in codes2)

# --- Pattern 3: map() generator arg ---
codes3 = [101, 118]
codes3.extend(map(int, ['97', '108']))
x3 = ''.join(chr(c) for c in codes3)

# --- Pattern 4: list comprehension arg ---
codes4 = [101, 118]
codes4.extend([x + 1 for x in [96, 107]])
x4 = ''.join(chr(c) for c in codes4)

# --- Pattern 5: Nested function call arg ---
codes5 = [101, 118]
codes5.extend(list(range(97, 99)))
x5 = ''.join(chr(c) for c in codes5)
