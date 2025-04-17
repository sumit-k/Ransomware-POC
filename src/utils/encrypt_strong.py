import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sys

def gnerate_key():
    password = b"password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

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
user_key = gnerate_key()
encrypt(file_path, user_key)
