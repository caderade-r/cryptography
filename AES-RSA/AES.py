# Author: Cade Melton
# Date: 9-15-2026
# File Description: Implementation of AES encryption/decryption

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES encryption function that uses CBC
def encrypt(plaintext: bytes, key: bytes):

    # generate random 16-byte IV
    iv = os.urandom(16)

    # create block cipher mode object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # pad plaintext to multiple of 16 bytes
    padded_data = pad(plaintext, AES.block_size)

    # encrypt padded plaintext after CBC chain
    ciphertext = cipher.encrypt(padded_data)

    # return iv and ciphertext as a single byte object so the server can handle it
    return iv, ciphertext

# AES decryption function that uses CBC
def decrypt(iv: bytes, ciphertext: bytes, key: bytes):

    # create block cipher mode object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # store padded plaintext after passing through CBC
    padded_plaintext = cipher.decrypt(ciphertext)

    # remove padding on padded plaintext
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext

# AES Execution Example

        # 1. Generate a valid 128-bit key (exactly 16 bytes)
        # aes_128_key = os.urandom(16)
    
        # 2. Define an exactly 18-byte message
        # message = b"Exactly 18 bytes!!"
        # print(f"Original Message Length: {len(message)} bytes")
    
        # 3. Encrypt
        # iv, cipher_text = AES.encrypt(message, aes_128_key)
        # print(f"Ciphertext Length (Padded): {len(cipher_text)} bytes") # Outputs 32 bytes
    
        # 4. Decrypt
        # decrypted_message = AES.decrypt(iv, cipher_text, aes_128_key)
        # print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")