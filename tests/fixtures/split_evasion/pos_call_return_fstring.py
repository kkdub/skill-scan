# Positive: f-string interpolation using call returns to build "system"
def get_sys() -> str:
    return "sys"


def get_tem() -> str:
    return "tem"


_cmd = f"{get_sys()}{get_tem()}"  # should detect "system"
