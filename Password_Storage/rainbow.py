import itertools
import hashlib
import time

CHARSET = (
    "1234567890"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "#$%^&*"
)

# Generate every possible N-character password and map its SHA256 hash back to it
def build_dictionary(n):
    table = {}
    for combo in itertools.product(CHARSET, repeat=n):
        pwd = "".join(combo)
        h = hashlib.sha256(pwd.encode()).hexdigest()
        table[h] = pwd
    return table

# Unsalted attack: build one dictionary, then look up every account's hash in it
def crack_file(accounts, n):
    # build the hash dictionary and record build time
    start = time.time()
    table = build_dictionary(n)
    build_time = time.time() - start

    # compare dictionary and account passwords
    # to find matching hash values and record search time
    results = {}
    lookup_start = time.time()
    for username, target_hash in accounts:
        results[username] = table.get(target_hash, "NOT_FOUND")
    lookup_time = time.time() - lookup_start

    # compute total time it took to build dictionary and search for matches
    total_time = build_time + lookup_time

    return results, build_time, lookup_time, total_time

# Salted attack on one account: try every N-character password with that account's salt until the hash matches
def crack_account(target_hash, salt_bytes, n):
    for combo in itertools.product(CHARSET, repeat=n):
        pwd = "".join(combo)
        h = hashlib.sha256(pwd.encode() + salt_bytes).hexdigest()
        if target_hash == h:
            return pwd
    return None

# Salted attack: repeat the brute-force search separately for every account, since each salt is unique
def crack_salted(accounts, n):
    results = {}
    per_account_times = {}
    total_start = time.time()

    for username, salt_str, target_hash in accounts:
        salt_bytes = int(salt_str).to_bytes(4, byteorder="big")

        start = time.time()
        pwd = crack_account(target_hash, salt_bytes, n)
        elapsed = time.time() - start

        results[username] = pwd if pwd else "NOT_FOUND"
        per_account_times[username] = elapsed

    total_time = time.time() - total_start
    return results, per_account_times, total_time

if __name__ == "__main__":

    print("1. Rainbow attack test (Unsalted)")
    print("2. Rainbow attack test (Salted)")
    choice = input("Please select an option: ")

    if choice == '1':
        # read accounts from passwords.txt
        accounts = []
        with open("passwords.txt") as f:
            for line in f:
                # get username and password hash
                user, h = line.strip().split(",")

                # format and store user data in variable container
                accounts.append([user, h])

        # get N
        N = int(input("Enter N (password length): "))

        # get results from rainbow attack functions
        results, build_time, lookup_time, total_time = crack_file(accounts, N)

        # print results
        print(f"\nDictionary build time: {build_time:.4f}s")
        print(f"Lookup time: {lookup_time:.4f}s")
        print(f"Total time: {total_time:.4f}s\n")
        for user, pwd in results.items():
            print(f"{user}: {pwd}")

    elif choice == '2':
        # read accounts from salted_passwords.txt
        accounts = []
        with open("salted_passwords.txt") as f:
            for line in f:
                # get username, salt, and password hash
                user, salt, h = line.strip().split(",")

                # format user data and store in variable container
                accounts.append([user, salt, h])

        # get N
        N = int(input("Enter N (password length): "))

        # get results from dictionary attack
        results, per_account_times, total_time = crack_salted(accounts, N)

        # print results
        print(f"\nTotal time: {total_time:.4f}s")
        for user, pwd in results.items():
            print(f"\n{user}: {pwd}  ({per_account_times[user]:.4f}s)")