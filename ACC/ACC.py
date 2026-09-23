# Advanced Ceasar Cipher Encryption/Decryption Program
#
# Author: Cade Melton
# Date: 8/26/2026

import string

alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
alphabet_size = len(alphabet)

plaintext = ""
index = 0

# prompts the user for a key input
def request_key():

    # init variables
    key = '0'

    # ensure user inputs a valid entry
    while (int(key) < 1 or int(key) > 25):
        key = input("Please enter a key (1-25): ")

    return key
    
# convert given string using provided key
def encrypt(plaintext, key):

    # loop through each character in the plaintext
    for index, char in enumerate(plaintext):

        # check if the character is a space or a letter
        if char != " ":

            # find the character's index in the alphabet
            old_char_index = alphabet.index(char)

            # calculate replacement character index
            new_char_index = old_char_index + int(key)

            # make sure the new index is within range of the alphabet
            if (new_char_index >= alphabet_size):
                new_char_index = alphabet_size - new_char_index

            # store new character in replacement string
            plaintext[index] = alphabet[new_char_index]

        # rejoin list into string
        ciphertext = "".join(plaintext)

    return ciphertext

def key_decrypt(ciphertext, key):

    # loop through each character in the ciphertext
    for index, char in enumerate(ciphertext):

        # check if char is not a space
        if char != " ":

            # find the old character's index in the alphabet
            old_char_index = alphabet.index(char)

            # find the replacement character's index
            new_char_index = old_char_index - int(key)

            # make sure the new character index is valid
            if (new_char_index < 0):
                new_char_index = new_char_index + alphabet_size

            # store new replacement string
            ciphertext[index] = alphabet[new_char_index]

        # rejoin list into string
        plaintext = "".join(ciphertext)
    
    return plaintext

# takes a filename input, 
def file_decrypt(ciphertext, filename):

    # variables
    found_key = None
    plaintext_list = []

    # create translation table for removing punctuation 
    punct_table = str.maketrans("", "", string.punctuation)

    # open the file
    with open(filename, "r", encoding="utf-8") as file:
        
        # read lines from file
        lines = file.readlines()
        new_line = ""

        # concatenate all lines into one line for vocab comparison
        for line in lines:
            line = line.replace('\n', " ")
            line = line.replace('\xa0', " ")
            line = line.strip().translate(punct_table)
            new_line += line
            new_line += " "

        # save vocab space indices
        vocab_spaces = [i for i, char in enumerate(new_line) if char == " "]

        # split each word by spaces
        vocab_words = new_line.split(" ")

        # split ciphertext into list of words
        cipher_words = ciphertext.split(" ")

        # iterate through each word in the ciphertext
        for cipher_index, words in enumerate(cipher_words):

            # apply keys to update ciphertext words one at a time for comparison
            for alph_index, alph_char in enumerate(alphabet):
                found = False

                # transform word into a list for comparison
                word_container = cipher_words[cipher_index]
                word_as_list = list(word_container)

                # iterate through each character in the word to update it
                for word_index, char in enumerate(word_as_list):

                    # set the test key
                    if found_key == None:
                        test_key = alph_index - 1
                    else:
                        test_key = found_key

                    # find the old character's index in the alphabet
                    old_char_index = alphabet.index(char)

                    # find the replacement character's index
                    new_char_index = old_char_index - int(test_key)

                    # make sure the new character index is valid
                    if (new_char_index < 0):
                        new_char_index = new_char_index + alphabet_size

                    # update letter
                    word_as_list[word_index] = alphabet[new_char_index]

                # save updated word for comparison
                word_container = "".join(word_as_list)

                # compare saved test word with each word in vocab
                for vocab_index, vocab_word in enumerate(vocab_words):
                    
                    # if a word matches one of the vocab words, save it to a list
                    if word_container == vocab_word.lower():
                        plaintext_list.append(word_container)
                        found_key = test_key
                        found = True
                        break

                # if the current word finds a match, move on to the next word
                if found == True:
                    found = False
                    break
        
        # restore spaces back to the plaintext
        plaintext = " ".join(plaintext_list)

    return found_key, plaintext


# takes data and key from user and encrypts the data using advanced ceasar cipher method
def ACC():
    # init local variables
    reply = '0'

    while (int(reply) != 1 and int(reply) != 2 and int(reply) != 3):
        reply = input("Please enter 1 for encrypting new data, 2 for decrypting with a key, or 3 for decrypting with a filename: ")

    if int(reply) == 1:
        # prompt user input 
        plaintext = input("Please enter the data you would like to encrypt: ") 

        # change to a list for easier comparison
        plaintext_list = list(plaintext)

        # request user key
        key = request_key()

        # collect new encrypted data
        ciphertext = encrypt(plaintext_list, key)

        # show result
        print(ciphertext)

    elif int(reply) == 2:
        # prompt user input
        ciphertext = input("Please input the ciphertext your would like to decipher: ")

        # convert ciphertext to a list for comparison
        ciphertext_list = list(ciphertext)

        # request user key
        key = request_key()

        # call decrypt function
        plaintext = key_decrypt(ciphertext_list, key)

        # print result
        print(plaintext)

    else:
        # prompt user input for decryption message
        ciphertext = input("Please input the ciphertext your would like to decipher: ")

        # convert ciphertext to list for comparison
        ciphertext_list = list(ciphertext)

        # prompt user input for vocab filename
        filename = input("Please input the name of the vocabulary file: ")

        # call brute force decryption function
        key, plaintext = file_decrypt(ciphertext, filename)

        print("key: " + str(key))
        print("plaintext: " + plaintext)

ACC()
