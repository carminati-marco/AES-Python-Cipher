""" Python AES-256 Message Encrypt/Decrypt (PAME)
    Simple program to encrypt and decrypt strings in python
    
    Version ALPHA 0.1.0
"""

# Begin importing standard libraries
from Crypto.Cipher import AES
import sys
import hashlib
import time
import getpass
import random
import os
import string
import base64

# Cryptographic key prompt function
def crypt_key():
    print "Enter a strong crypographic key (at least 16 characters)"
    print "Key input is not echoed to terminal. Coninue typing normally"
    
    # Starts loop in case key is too short
    while True:
        user_input = getpass.getpass("Key: ")
        
        # Check length of user defined cryptographic key
        if len(user_input) <= 15:
            print "Please enter a key with at least 16 characters length"
        else:
            break
    # Uses sha256 to create a 32 byte long hash of user_input for AES-256
    key = hashlib.sha256(user_input).digest()
    return key

# Random IV generator (random string hashed with SHA-256 and truncated
def IV_generator():

    # Sets characterset and length of random string
    charset = string.ascii_uppercase + string.digits
    size = 32
    
    # Generates random number
    number = "".join(random.choice(charset) for _ in range(size))
    
    # Converts random number into sha256 hash truncated to 16 bytes
    IV = hashlib.sha256(number).digest()[0:16]
    return IV
    

# AES-256 encryption function
def aes_encrypt(key, IV, plaintext):
    
    # Sets encryption mode (default is CBC)
    mode = AES.MODE_CBC
    
    # Start encryption proccedure
    encryptor = AES.new(key, mode, IV)
    aes_ciphertext = encryptor.encrypt(plaintext)
    
    # Convert binary IV and ciphertext into base64 ascii
    base64_ciphertext = base64.b64encode(aes_ciphertext)
    base64_IV = base64.b64encode(IV)
    
    return base64_ciphertext
    
def aes_decrypt(key, IV, ciphertext):
    
    # Sets the decryption mode (default is CBC)
    mode = AES.MODE_CBC
    
    # Convert base64 ciphertext into aes_ciphertext
    aes_ciphertext = base64.b64decode(ciphertext)
    
    # Start decryption proccedure
    decryptor = AES.new(key, mode, IV)
    plaintext = decryptor.decrypt(aes_ciphertext)
    
    return plaintext
    

# Sets environment variables
key = crypt_key()
IV = IV_generator()
plaintext = raw_input("Plaintext: ")
ciphertext = aes_encrypt(key, IV, plaintext)
print ciphertext
print aes_decrypt(key, IV, ciphertext)


    
