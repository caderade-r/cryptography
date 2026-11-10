import os
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from Crypto.Signature import pss
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# AES encryption (CBC mode)
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

# AES decryption (CBC mode)
def decrypt(iv: bytes, ciphertext: bytes, key: bytes):

    # create block cipher mode object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # store padded plaintext after passing through CBC
    padded_plaintext = cipher.decrypt(ciphertext)

    # remove padding on padded plaintext
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext

# Generate new HMAC
def new_hmac(key, message):
    """Return the raw HMAC-SHA256 tag (bytes)."""
    return HMAC.new(key, msg=message, digestmod=SHA256).digest()

# Verify HMAC
def verify_hmac(key, message, mac):
    """Return True if mac is a valid HMAC-SHA256 of message under key."""
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    try:
        h.verify(mac)
        return True
    except ValueError:
        return False

# Generate RSA key pair
def generate_keys(private_path="alice_private.pem", public_path="alice_public.pem"):
    key = RSA.generate(2048)
    with open(private_path, "wb") as f:
        f.write(key.export_key())
    with open(public_path, "wb") as f:
        f.write(key.publickey().export_key())

# Load RSA key pair
def load_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

# used to pass alice's random 32-byte key to bob safely
def wrap_key(public_key, k):
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(k)

# used by bob to unwrap alice's 32-byte key
def unwrap_key(private_key, wrapped):
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(wrapped)

# Sign RSA key pair
def sign(private_key, message):
    h = SHA256.new(message)
    return pss.new(private_key).sign(h)

# Verify RSA signature
def verify_signature(public_key, message, signature):
    h = SHA256.new(message)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False