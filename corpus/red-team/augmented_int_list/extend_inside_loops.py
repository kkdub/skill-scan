# Red-team: .extend() inside loops and control flow
# Target: _handle_extend_call
# Expected: EXEC-002 detection where noted

# --- Pattern 1: .extend() inside for loop with literal ---
codes = [101]
for _ in range(1):
    codes.extend([118, 97, 108])
x = ''.join(chr(c) for c in codes)

# --- Pattern 2: .extend() inside nested for ---
def nested_extend_loop():
    codes = []
    for chunk in [[101, 118], [97, 108]]:
        codes.extend(chunk)  # non-literal arg, should shadow
    x = ''.join(chr(c) for c in codes)

# --- Pattern 3: .extend() in while loop ---
def while_extend():
    codes = [101, 118]
    i = 0
    while i < 1:
        codes.extend([97, 108])
        i += 1
    x = ''.join(chr(c) for c in codes)

# --- Pattern 4: Multiple .extend() calls ---
codes2 = []
codes2.extend([101])
codes2.extend([118])
codes2.extend([97])
codes2.extend([108])
x2 = ''.join(chr(c) for c in codes2)

# --- Pattern 5: .extend() inside try-except ---
def try_extend():
    codes = [101, 118]
    try:
        codes.extend([97, 108])
    except Exception:
        pass
    x = ''.join(chr(c) for c in codes)

# --- Pattern 6: .extend() inside if ---
def conditional_extend():
    codes = [101, 118]
    if True:
        codes.extend([97, 108])
    x = ''.join(chr(c) for c in codes)
