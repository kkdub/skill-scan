# Negative: functions returning safe strings, no dangerous name assembled
def get_hello() -> str:
    return "hello"


def get_world() -> str:
    return "world"


_result = get_hello() + get_world()  # "helloworld" -- safe, no finding
