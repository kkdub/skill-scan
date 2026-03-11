# Positive: split base64-encoded payload (decodes to 'import os; os.system('cmd')')
a = "aW1wb3J0IG9zOyBvcy"
b = "5zeXN0ZW0oJ2NtZCcp"
payload = a + b
