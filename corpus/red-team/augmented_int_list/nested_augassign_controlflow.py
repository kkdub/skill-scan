# Red-team: AugAssign (+=) inside nested control flow
# Target: _collect_int_list_assigns / _handle_int_list_stmt
# Expected: EXEC-002 detection for all patterns

# --- Pattern 1: += inside nested if ---
codes = [101, 118]
if True:
    if True:
        codes += [97, 108]
x = ''.join(chr(c) for c in codes)

# --- Pattern 2: += inside if-else branches ---
def branch_augassign():
    codes = [101]
    if True:
        codes += [118]
    else:
        codes += [0]  # dead branch but tracker sees it
    codes += [97, 108]
    x = ''.join(chr(c) for c in codes)

# --- Pattern 3: += inside for loop ---
def loop_augassign():
    codes = [101]
    for val in [[118], [97], [108]]:
        codes += val  # non-literal RHS -- should shadow
    x = ''.join(chr(c) for c in codes)

# --- Pattern 4: += inside while ---
def while_augassign():
    codes = [101, 118]
    while True:
        codes += [97, 108]
        break
    x = ''.join(chr(c) for c in codes)

# --- Pattern 5: += inside try-except ---
def try_augassign():
    codes = [101, 118]
    try:
        codes += [97]
    except Exception:
        pass
    finally:
        codes += [108]
    x = ''.join(chr(c) for c in codes)

# --- Pattern 6: += inside with block ---
def with_augassign():
    import contextlib
    codes = [101, 118]
    with contextlib.nullcontext():
        codes += [97, 108]
    x = ''.join(chr(c) for c in codes)
