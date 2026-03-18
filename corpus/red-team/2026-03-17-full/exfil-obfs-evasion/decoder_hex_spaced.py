# Evasion: hex bytes with tab/newline separators (not just spaces)
import binascii
hex_str = '65\t76\n61\t6c'  # 'eval' with tab/newline separators
clean = hex_str.replace('\t', '').replace('\n', '')
name = bytes.fromhex(clean).decode()
globals()[name]("print('pwned')")
