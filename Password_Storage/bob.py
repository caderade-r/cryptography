import os
import crypto_utils

def get_keys(): 
    # get k_c
    with open('K_c.txt', 'rb') as f1:
        k_c = f1.read().strip()
    if len(k_c) != 32:
        raise ValueError(f"Shared key is not equal to 32 bytes, got {len(k_c)}")

    with open("K_i.txt", "rb") as f2:
        k_i = f2.read().strip()
    if len(k_i) != 32:
        raise ValueError(f"Shared key is not equal to 32 bytes, got {len(k_i)}")

    return k_c, k_i

if __name__ == "__main__":
    # prompt user input
    print("1. AES encryption with HMAC generation verification")
    print("2. AES encryption with RSA signature verification")
    choice = input("Please select an option: ")

    if choice == '1':
        K_c, K_i = get_keys()

        with open("cmac.txt", "rb") as f:
            data = f.read()

        iv = data[:16]
        ciphertext = data[16:-32]
        mac = data[-32:]

        try:
            message = crypto_utils.decrypt(iv, ciphertext, K_c)
        except ValueError:
            # padding is invalid -> ciphertext or iv was corrupted
            print("Decryption failed: ciphertext appears corrupted.")
            print("HMAC verification unsuccessful.")
        else:
            try:
                text = message.decode('utf-8')
            except UnicodeDecodeError:
                text = message.decode('utf-8', errors='replace')
                print("Warning: decrypted bytes are not valid UTF-8 text.")

            print(f"Decrypted message: '{text}'")

            if crypto_utils.verify_hmac(K_i, message, mac):
                print("HMAC verification successful.")
            else:
                print("HMAC verification unsuccessful.")

    elif choice == '2':
        alice_public = crypto_utils.load_key("alice_public.pem")
        bob_private = crypto_utils.load_key("bob_private.pem")

        with open("csig.txt", "rb") as f:
            data = f.read()

        iv = data[:16]
        ciphertext = data[16:-512]
        wrapped_key = data[-512:-256]
        signature = data[-256:]

        try:
            key = crypto_utils.unwrap_key(bob_private, wrapped_key)
            message = crypto_utils.decrypt(iv, ciphertext, key)
        except ValueError:
            print("Decryption failed: ciphertext or wrapped key appears corrupted.")
            print("RSA verification unsuccessful.")
        else:
            try:
                text = message.decode('utf-8')
            except UnicodeDecodeError:
                text = message.decode('utf-8', errors='replace')
                print("Warning: decrypted bytes are not valid UTF-8 text.")

            print(f"Decrypted message: '{text}'")

            if crypto_utils.verify_signature(alice_public, message, signature):
                print("RSA verification successful.")
            else:
                print("RSA verification unsuccessful.")