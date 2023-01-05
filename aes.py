# AES 256 encryption/decryption using pycryptodome library

from base64 import b64encode, b64decode
import hashlib
from Crypto.Cipher import AES
import os
from Crypto.Random import get_random_bytes

def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(plain_text)
    return {
        'cipher_text': cipher_text,
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }
        


def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = enc_dict['cipher_text']
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted


def main():
    password = input("Password: ")

    # First let us encrypt secret message
    with open('mysong_1.mp3', "rb") as file:
        # read all file data
        file_data = file.read()
    
        
    encrypted = encrypt(file_data, password)
    print(encrypted)

    with open('mysong_1.mp3', "wb") as file:
        file.write(encrypted['cipher_text'])    
    
    with open('mysong_1.mp3', "rb") as file:
        # read all file data
        file_data = file.read()
  
    

        
    decrypted = decrypt(encrypted, password)
    
    
    with open('mysong_1.mp3', "wb") as file:
        file.write(decrypted)    

main()