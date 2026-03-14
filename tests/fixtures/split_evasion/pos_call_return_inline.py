# Positive: direct inline concatenation get_a() + get_b() to "exec"
def get_a() -> str:
    return "ex"


def get_b() -> str:
    return "ec"


_result = get_a() + get_b()  # should detect "exec"
