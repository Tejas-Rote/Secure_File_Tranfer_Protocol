# -*- coding: utf-8 -*-


# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

################################IMPORTS

from fsplit.filesplit import Filesplit
import os
from base64 import b64encode, b64decode
import hashlib
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from Crypto.Random import get_random_bytes
import random

##########################################GLOBAL FERNETS

fernetkeys=[]






#########################################FILE SPLIT AKA PREPROCESSING

fs = Filesplit()

def split_cb(f, s):
    print("file: {0}, size: {1}".format(f, s))

fs.split(file="mysong.mp3", split_size=900000, output_dir=os.getcwd()+"\song", callback=split_cb)


os.chdir("song")
print(os.listdir())

songlist=os.listdir()[1:]
print(songlist)



#################################################################DES



def write_key():
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
        
def load_key():
    """
    Loads the key from the current directory named `key.key`
    """
    return open("key.key", "rb").read()

write_key()

key = load_key()
print(key)






def DESencrypt(filename, key,itr):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """
    f = Fernet(key)
    print(f)
    fernetkeys.append(f)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
        
        # encrypt data
    encrypted_data = f.encrypt(file_data)
        
        # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def DESdecrypt(filename, key,itr):
    print("inside decryptor")
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """
    f = Fernet(key)
    print(f)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)
        





##############################################AES



def AESencrypt(plain_text, password):
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
        


def AESdecrypt(enc_dict, password):
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


##############################################################


for i in songlist:
    #DESencrypt(i,key,1)
    a=random.randint(0,1)
    '''if a==1:
         DESencrypt(i,key,1)   
    if a==0:
        AESencrypt(i,key)
    '''
    #encrypt(i,key)
    #decrypt(i,key)

print(fernetkeys)
print("Decrypt files?")
ch=int(input())

if ch==1:
    for i in songlist:
        DESdecrypt(i,key,1)
    