# Positive: function returns fragments, caller assigns and concatenates to "eval"
def get_prefix() -> str:
    return "ev"


def get_suffix() -> str:
    return "al"


x = get_prefix()
y = get_suffix()
_result = x + y  # should detect "eval"
