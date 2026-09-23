import AES
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time

AES_KEY_SIZES = [16, 24, 32]
RSA_KEY_SIZES = [1024, 2048, 4096]
NUM_TRIALS = 100

def measure_aes_performance(message):
    print("\n--- AES Performance (100 trials each) ---")
    for key_size in AES_KEY_SIZES:
        key = os.urandom(key_size)
 
        # Average encryption time
        start = time.perf_counter()
        for _ in range(NUM_TRIALS):
            iv, ciphertext = AES.encrypt(message, key)
        avg_encrypt_time = (time.perf_counter() - start) / NUM_TRIALS
 
        # Average decryption time
        start = time.perf_counter()
        for _ in range(NUM_TRIALS):
            AES.decrypt(iv, ciphertext, key)
        avg_decrypt_time = (time.perf_counter() - start) / NUM_TRIALS
 
        print(f"AES-{key_size * 8}: "
              f"avg encryption time = {avg_encrypt_time * 1000:.4f} ms, "
              f"avg decryption time = {avg_decrypt_time * 1000:.4f} ms")

def measure_rsa_performance(message):
    print("\n--- RSA Performance (100 trials each) ---")
    for bits in RSA_KEY_SIZES:
        key_pair = RSA.generate(bits)
        encrypt_cipher = PKCS1_OAEP.new(key_pair.publickey())
        decrypt_cipher = PKCS1_OAEP.new(key_pair)
 
        # Average encryption time
        start = time.perf_counter()
        for _ in range(NUM_TRIALS):
            ciphertext = encrypt_cipher.encrypt(message)
        avg_encrypt_time = (time.perf_counter() - start) / NUM_TRIALS
 
        # Average decryption time (decrypt the same ciphertext repeatedly)
        start = time.perf_counter()
        for _ in range(NUM_TRIALS):
            decrypt_cipher.decrypt(ciphertext)
        avg_decrypt_time = (time.perf_counter() - start) / NUM_TRIALS
 
        print(f"RSA-{bits}: "
              f"avg encryption time = {avg_encrypt_time * 1000:.4f} ms, "
              f"avg decryption time = {avg_decrypt_time * 1000:.4f} ms")


if __name__ == "__main__":

    print("Select a test to run:")
    print("1. Test AES with an 18-byte message and 128-bit key")
    print("2. Test RSA with an 18-byte message and 2048-bit key")
    print("3. Measure performance for AES with 128, 192, and 256-bit keys \n and RSA with 1024, 2048, and 4096-bit keys")

    choice = input("Please enter the test you would like to run (1-3): ")

    if choice == "1":
        # 1. Generate a valid 128-bit key (exactly 16 bytes)
        aes_128_key = os.urandom(16)

        # 2. write the key to secret_key.txt
        with open("secret_key.txt", "wb") as f:
            f.write(aes_128_key)

        # 3. Define an exactly 18-byte message
        message = input("Enter a message: ").encode('utf-8')
        print(f"Original Message Length: {len(message)} bytes")

        # 4. Encrypt
        iv, cipher_text = AES.encrypt(message, aes_128_key)
        print(f"Ciphertext Length (Padded): {len(cipher_text)} bytes") # Outputs 32 bytes

        # 5. Write encrypted message to ctext.txt
        with open("ctext.txt", "wb") as f:
            f.write(iv + cipher_text)

    elif choice == "2":
        # 1. prompt user for a message
        message = input("Enter a message: ").encode('utf-8')

        # 2. get Bob's public key from public_keys.txt
        with open("public_keys.txt", "rb") as f:
            bob_public_key = RSA.import_key(f.read())

        # 3. encrypt the message using Bob's public key
        cipher = PKCS1_OAEP.new(bob_public_key)
        encrypted_message = cipher.encrypt(message)

        # 4. write ciphertext to ctext.txt
        with open("ctext.txt", "wb") as f:
            f.write(encrypted_message)

        print("Message encrypted and saved to ctext.txt, run bob.py to decrypt")

    elif choice == "3":
        message = input("Enter a message: ").encode('utf-8')
        measure_aes_performance(message)
        measure_rsa_performance(message)
