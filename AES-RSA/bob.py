import os
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import AES

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_keys.txt"

def get_or_create_keypair():
    just_created = False

    if not os.path.exists(PRIVATE_KEY_FILE):
        key_pair = RSA.generate(2048)

        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(key_pair.export_key())

        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(key_pair.publickey().export_key())

        just_created = True

    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = RSA.import_key(f.read())

    return private_key, just_created


if __name__ == "__main__":

    # Always load (or create, on first run) the same private key.
    private_key, just_created = get_or_create_keypair()

    if just_created:
        print("No existing key found - generated a new RSA key pair.")
        print(f"Public key written to {PUBLIC_KEY_FILE}.")
        print("Run alex.py now to encrypt a message with this key.")
        sys.exit(0)

    choice = input("Which test is being run? (1 or 2): ")

    if choice == "1":
        # 1. read the key from secret_key.txt
        with open("secret_key.txt", "rb") as f:
            aes_128_key = f.read()

        # 2. read from ctext.txt
        with open("ctext.txt", "rb") as f:
            data = f.read()

        # 3. Extract iv and ciphertext
        iv = data[:16]
        cipher_text = data[16:]

        # 4. Decrypt
        decrypted_message = AES.decrypt(iv, cipher_text, aes_128_key)
        print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")

    elif choice == "2":
        # 1. read the encrypted message from ctext.txt
        with open("ctext.txt", "rb") as f:
            encrypted_message = f.read()

        # 2. decrypt the message using Bob's private key
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher.decrypt(encrypted_message)

        print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")