# Negative: ordinary slicing on non-dangerous strings -- must NOT trigger findings
greeting = "hello world"
first_word = greeting[:5]
last_word = greeting[6:]
middle = greeting[2:8]
