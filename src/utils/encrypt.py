from cryptography.fernet import Fernet
import sys

def gnerate_key(key_file):
    user_key = input("Generate new key (y/n) ")
    if user_key.lower() == 'y':
        user_key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(user_key)
    else:
        with open(key_file, 'rb') as f:
            user_key = f.read()

    return user_key

def encrypt(file_path, key): 

    # using the generated key
    fernet = Fernet(key)

    # opening the original file to encrypt
    with open(file_path, 'rb') as file:
        original = file.read()

    # encrypting the file
    encrypted = fernet.encrypt(original)

    # opening the file in write mode and
    # writing the encrypted data
    with open(file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    

file_path = sys.argv[1]
user_key = gnerate_key("filekey.key")
encrypt(file_path, user_key)
