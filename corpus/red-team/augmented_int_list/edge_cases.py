# Red-team: Edge cases for augmented int-list tracking
# Various boundary conditions and unusual patterns

# --- Pattern 1: Empty initial list, built entirely via += ---
codes = []
codes += [101, 118, 97, 108]
x = ''.join(chr(c) for c in codes)

# --- Pattern 2: += with empty list (no-op) ---
codes2 = [101, 118, 97, 108]
codes2 += []
x2 = ''.join(chr(c) for c in codes2)

# --- Pattern 3: .extend() with empty list (no-op) ---
codes3 = [101, 118, 97, 108]
codes3.extend([])
x3 = ''.join(chr(c) for c in codes3)

# --- Pattern 4: += on class-scoped variable ---
class Evasion:
    codes = [101, 118]
    codes += [97, 108]
    x = ''.join(chr(c) for c in codes)

# --- Pattern 5: += in async function ---
async def async_augassign():
    codes = [101, 118]
    codes += [97, 108]
    x = ''.join(chr(c) for c in codes)

# --- Pattern 6: Single-element list += many times ---
def single_element_chain():
    c = [101]
    c += [120]
    c += [101]
    c += [99]
    x = ''.join(chr(i) for i in c)

# --- Pattern 7: += with non-Add op should NOT track ---
codes4 = [101, 118, 97, 108]
codes4 *= 1  # Mult, not Add -- should be ignored
x4 = ''.join(chr(c) for c in codes4)
