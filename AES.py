""" Python AES-256 Message Encrypt/Decrypt (PAME)
    Simple program to encrypt and decrypt strings in python
    
    Version BETA 0.3.5
"""

# Begin importing standard libraries
from Crypto.Cipher import AES
import hashlib
import getpass
import random
import string
import sys
import time
import base64

def menuscreen():
    """ Prompts the user for their actions of either encrypting a
    string or decrypting a string """
    
    # Prompt loop
    while True:
    
        # TUI prompt with menu options
        print "Welcome to AES-256 encrypter. Please your action: "
        print "    (1) Encrypt a message in AES-256"
        print "    (2) Decrypt a message in AES-256"
        print "    (3) Exit program"
        
        # Prompt user for response
        menu_choice = raw_input("Response: ")
        
        # Begin if/else block to determine response
        if menu_choice == "1":
            print "AES-256 encryption service started"
            encrypt(key_prompt(), IV_prompt(False), text_prompt(False))
            
        elif menu_choice == "2":
            print "AES-256 decryption service started"
            decrypt(key_prompt(), IV_prompt(True), text_prompt(True))
            
        elif menu_choice == "3":
            print "Exiting program. Goodbye"
            sys.exit()
            
        else:
            print "Please select 1, 2, or 3:"
            
def key_prompt():
    """ Prompts the user to enter a key to encrypt and decrypt the ciphertext
    into plaintext. Supports both encrypting and decrypting. """
    
    # Prompts user to enter key
    print "Enter the cryptographic key used to encrypt/decrypt the message"
    
    # Length checking loop
    while True:
        user_input = getpass.getpass("    Key: ")
        
        if user_input <= 8:
            print "The key you entered is too short. Please try again"
        
        else:
            break
    
    # Hashes the key to create 32 byte string and creates UTF-8 friendy base64
    key = hashlib.sha256(user_input).digest()
    key_base64 = base64.b64encode(key)
    
    print "Your key is registered as: %s" % (key_base64)
    return key
    
    
    
    
def IV_prompt(decrypt):
    """ Prompts the user for a IV. Generates random initializatio vector if
    encrypting, and prompts the user for a previous one when decrypting """
    
    # Decision branch to function differently when encrypting/decrypting
    if decrypt:
        print "You must enter the base64 encoding of your IV to decrypt"
        IV_base64 = raw_input("    IV: ")
        IV = base64.b64decode(IV_base64)
        return IV
        
    else:
        print "A IV is needed in order to encrypt the message."
        print "IVs are typically randomly generated. Generate a IV?"
        
        # Prompt loop
        while True:
            
            # Options
            print "    (1) Generate random IV (recommanded)"
            print "    (2) Enter your own IV"
            
            # If/else block to determine response
            IV_choice = raw_input("(1/2): ")
            if IV_choice == "1":
                print "A IV is being generated..."
                
                # Defines character sets
                ascii = string.ascii_letters
                digits = string.digits
                punct = string.punctuation
                charset = ascii + digits + punct
                
                # Size of string
                size = 32
                
                # Generates random string
                rand = ""
                rand.join(random.choice(charset) for i in range(size))
                
                # Creates IV from random string
                IV = hashlib.sha256(rand).digest()[0:16]
                IV_base64 = base64.b64encode(IV)
                
                # Returns IV to the user
                print "The IV in base64 is printed below. You must use it to "
                print "decrypt the ciphertext. It is ok to send the IV with the"
                print "ciphertext - an attacker cannot us the IV against you"
                
                print "    IV: %s" % (IV_base64)
                return IV
                break
                
            elif IV_choice == "2":
                
                # Prompts the user for their custom IV
                print "You will enter your own string to be used as the IV"
                IV_input = raw_input("    IV:")
                
                # Hashes user IV into SHA-256 and also base64
                IV = hashlib.sha256(IV_input).digest[0:16]
                IV_base64 = base64.b64encode(IV)
                
                # Returns IV to user
                print "The IV in base64 is printed below. You must use it to "
                print "decrypt the ciphertext. It is ok to send the IV with the"
                print "ciphertext - an attacker cannot us the IV against you"
                
                print "    IV: %s" % (IV_base64)
                return IV
                break
            
            else:
                print "Error, please select 1 or 2"
        
def text_prompt(decrypt):
    """ Prompts the user for either the ciphertext, or the plaintext of the
    message depending on if he wants to encrypt or decrypt the message """
    
    # Decision branch to function differently when encrypting/decrypting
    if decrypt:
        
        # Prompts user to input ciphertext to decrypt message
        print "Please enter your ciphertext for decryption encoded as base64"
        ciphertext_base64 = raw_input("    Ciphertext: ")
        ciphertext = base64.b64decode(ciphertext_base64)
        
        return ciphertext
        
    else:
        
        # Prompts user to input plaintext to encrypt ciphertext
        print "Please enter your plaintext for encryption encoded as base64"
        plaintext = raw_input("    Plaintext: ")
        
        return plaintext
    
def encrypt(key, IV, plaintext):
    """ Main encryption function. Supports the CBC mode on default and accepts
    IV, plaintext, and key as input """
    
    # Sets encryption mode
    mode = AES.MODE_CBC
    
    # Main encryption function
    encryptor = AES.new(key, mode, IV)
    ciphertext = encryptor.encrypt(plaintext)
    
    # Converts binary ciphertext into base64
    ciphertext_base64 = base64.b64encode(ciphertext)
    
    # Gives user encrypted base64 string
    print "You have successfully encrypted your message using"
    print "AES-256. The result is given to you encoded in"
    print "base64. You must decode it into it's raw form before"
    print "using it. This program does it for you automatically"
    print "when you select decrypt."
    
    print ciphertext_base64


def decrypt(key, IV, ciphertext):
    """ Main decryption function. Decrypts the ciphertext (which would already
    be turned from base64 to raw binary via text_prompt() """
    
    # Sets encryption mode
    mode = AES.MODE_CBC
    
    # Main encryption function
    decryptor = AES.new(key, mode, IV)
    plaintext = decryptor.decrypt(ciphertext)
    
    # Gives the user the result from decryption
    print "We have decrypted the message from your information"
    print "If it is gibberish, make sure to check if the IV, "
    print "key, or ciphertext is correct"
    
    print plaintext
        
menuscreen()
