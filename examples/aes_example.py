"""
Example student code: AES-EAX authenticated encryption.
Run: cryptoviz examples/aes_example.py
"""

import os
from Crypto.Cipher import AES

# Generate a random 128-bit key
key = os.urandom(16)

# Encrypt a message
plaintext = b"Hello, cryptography class!"
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

print(f"Key        : {key.hex()}")
print(f"Nonce      : {cipher.nonce.hex()}")
print(f"Ciphertext : {ciphertext.hex()}")
print(f"Auth tag   : {tag.hex()}")

# Decrypt and verify
cipher2 = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
decrypted = cipher2.decrypt_and_verify(ciphertext, tag)
print(f"Decrypted  : {decrypted.decode()}")
