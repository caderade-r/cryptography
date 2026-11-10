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

def get_message():
    while True:
        msg = input("Input an 18-byte message: ").encode('utf-8')
        if len(msg) == 18:
            return msg
        print(f"Message is not equal to 18 bytes, got {len(msg)}")

if __name__ == "__main__":
    # prompt user input
    print("1. AES encryption with HMAC generation")
    print("2. AES encryption with RSA signature")
    choice = input("Please select an option: ")

    if choice == '1':
        # get both shared keys
        K_c, K_i = get_keys()

        # get input message from Alice
        message = get_message()

        # generate HMAC (SHA-256) for message with K_i
        mac = crypto_utils.new_hmac(K_i, message)

        # print mac to verify it was successfully generated
        print("HMAC successfully generated")

        # encrypt message with AES
        iv, ciphertext = crypto_utils.encrypt(message, K_c)

        # write HMAC, iv, and ciphertext to CMAC file
        with open("cmac.txt", "wb") as f:
            f.write(iv + ciphertext + mac)

        print("Data successfully written to 'cmac.txt'")

    elif choice == '2':
        # generate alice's key pair if it does not exist
        if not os.path.exists("alice_private.pem"):
            crypto_utils.generate_keys()
        if not os.path.exists("bob_private.pem"):
            crypto_utils.generate_keys("bob_private.pem", "bob_public.pem")

        # get alice's private key
        private_key = crypto_utils.load_key("alice_private.pem")
        bob_public = crypto_utils.load_key("bob_public.pem")

        # get 18-byte message
        message = get_message()

        # sign message with private key
        signature = crypto_utils.sign(private_key, message)

        # confirm signature
        print("Message has been signed.")

        # generate random 32-byte key
        rand_key = os.urandom(32)

        # confirm key generation
        print("Random key has been generated.")

        # encrypt message using AES
        iv, ciphertext = crypto_utils.encrypt(message, rand_key)
        wrapped_key = crypto_utils.wrap_key(bob_public, rand_key)

        # write iv, ciphertext, and signature to csig.txt
        with open("csig.txt", "wb") as f:
            f.write(iv + ciphertext + wrapped_key + signature)

        # confirm that data was written successfully
        print("Data was successfully written to 'csig.txt'.")


