"""
Example student code with common mistakes (for testing error detection).
Run: cryptoviz examples/bad_crypto.py
"""

import hashlib
from Crypto.Cipher import AES

# BAD: hardcoded key
key = b"mysecretkey12345"

# BAD: ECB mode (reveals patterns)
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(b"Hello World!!!!!")

# BAD: MD5 for hashing sensitive data
digest = hashlib.md5(ciphertext).hexdigest()

print(f"Ciphertext : {ciphertext.hex()}")
print(f"MD5 digest : {digest}")
