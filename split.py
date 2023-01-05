
"""
This is a temporary script file.
"""


# IMPORTS
import time
from fsplit.filesplit import Filesplit
import os
from base64 import b64encode, b64decode
import hashlib
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from Crypto.Random import get_random_bytes
import random
import tkinter as tk
from tkinter import filedialog
from tkinter.ttk import Progressbar
import shutil
from tkinter import *
from tkinter import ttk

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import os

from Crypto.Cipher import DES3
from hashlib import md5


import RSA_encryption
# GLOBAL FERNETS AND VARIABLES

fernetkeys = []

aestokenlist = []

enclist = []

selectedfilename = "this is it"
selectedfilepath = ""
# songlist=[]

root = tk.Tk()
root.geometry("600x400+10+10")
name_var = tk.StringVar()
passw_var = tk.StringVar()
passwd_var = tk.StringVar()
globalpwd = ''


keyPair = RSA.generate(3072)

pubKey = keyPair.publickey()
print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
print(pubKeyPEM.decode('ascii'))

print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
print(privKeyPEM.decode('ascii'))


def openNewWindow():
    # Toplevel object which will
    # be treated as a new window
    newWindow = tk.Toplevel(root)
    # sets the title of the
    # Toplevel widget
    newWindow.title("New Window")
    # sets the geometry of toplevel
    newWindow.geometry("400x400+10+10")
    # frame = Frame(newWindow, relief='sunken', bg="black")
    # frame.pack(fill=BOTH, expand=True, padx=10, pady=20)
    # A Label widget to show in toplevel

    name_label = tk.Label(newWindow, text='Username',
                          font=('calibre', 10, 'bold'))

    name_label.pack(pady=100)
    # creating a entry for input
    # name using widget Entry
    name_entry = tk.Entry(newWindow, textvariable=name_var,
                          font=('calibre', 10, 'normal'))

    # creating a label for password
    passw_label = tk.Label(
        newWindow, text='Encryption Password:', font=('calibre', 10, 'bold'))

    # creating a entry for password
    passw_entry = tk.Entry(newWindow, textvariable=passwd_var, font=(
        'calibre', 10, 'normal'), show='*')
    decr_btn = tk.Button(newWindow, text='Decrypt', command=decryptfile)
    name_label.grid(row=3, column=0)
    name_entry.grid(row=3, column=1)
    passw_label.grid(row=4, column=0)
    passw_entry.grid(row=4, column=1)
    decr_btn.grid(row=5, column=1)


def browseFiles():

    global selectedfilepath
    selectedfilepath = filedialog.askopenfilename(initialdir="/",
                                                  title="Select a File",
                                                  filetypes=(("MP3 files",
                                                              "*.mp3*"),
                                                             ("all files",
                                                              "*.*")))
    splitpath = selectedfilepath.split('/')
    global selectedfilename
    selectedfilename = splitpath[-1]

    # Change label contents
    for i in range(10):
        progress['value'] = progress['value']+i*10
        root.update_idletasks()
        time.sleep(0.05)
    label_file_explorer.configure(text="File Opened: "+selectedfilename)


# Create the root window

# Set window title
root.title('File Storage System')
root.config(pady=10)


# Set window background color


# Create a File Explorer label
label_file_explorer = tk.Label(
    root, text="File Selector", fg="blue", font=('calibre', 12, 'normal'))


button_explore = tk. Button(root, text="Browse Files", font=(
    'calibre', 12, 'normal'), command=browseFiles)


# Grid method is chosen for placing
# the widgets at respective positions
# in a table like structure by
# specifying rows and columns


# FILE SPLIT AKA PREPROCESSING

def split_cb(f, s):
    print("file: {0}, size: {1}".format(f, s))


def merge_cb(f, s):
    print("file: {0}, size: {1}".format(f, s))


def filesplit():
    print(selectedfilename)

    fs = Filesplit()
    fs.split(file=selectedfilename, split_size=500000,
             output_dir=os.getcwd()+"\song", callback=split_cb)

    os.chdir("song")
    print(os.listdir())

    songlis = os.listdir()[1:]
    songlist = songlis
    print(songlis)
    updt = 100/len(songlis)
    for i in range(len(songlis)):
        progress2['value'] = progress['value']+updt
        root.update_idletasks()
        time.sleep(0.1)
    return songlis


###################################### MERGE#####################################


def mergefiles():
    os.chdir('song')
    fs1 = Filesplit()
    fs1.merge(input_dir=os.getcwd(), callback=merge_cb)
    source = os.getcwd()+"\mysong.mp3"
    path_parent = os.path.dirname(os.getcwd())
    os.chdir(path_parent)
    source = os.getcwd()+"\mysong.mp3"
    destination = os.getcwd()+"\mysongdecrypted.mp3"
    dest = shutil.copy(source, destination)


# DES
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


# TDES

def write_tdes_key():
    """
    Generates a key and save it into a file
    """
    key = 'BX2nIiHMEP0H82xYavUZpFszC7RKsFWn0xlUig6gsJA='
    key_hash = md5(key.encode('ascii')).digest()

    tdes_key = DES3.adjust_key_parity(key_hash)

    with open("tdes_key.key", "wb") as key_file:
        key_file.write(tdes_key)


def load_tdes_key():
    """
    Loads the key from the current directory named `key.key`
    """
    return open("tdes_key.key", "rb").read()


write_key()

key = load_key()
# encryptkeyrsa()
write_tdes_key()
tdes_key = load_tdes_key()
print(key)


# 3DES
def DES3encrypt(filename, tdes_key, itr):
    print("3DES encrypt")
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')
    print(cipher)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    new_file_data = cipher.encrypt(file_data)

    with open(filename, "wb") as file:
        file.write(new_file_data)


def DES3decrypt(filename, tdes_key, itr):
    print("3DES decrypt")
    decipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')
    print(decipher)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    new_file_data = decipher.encrypt(file_data)

    with open(filename, "wb") as file:
        file.write(new_file_data)


# DES

def DESencrypt(filename, key, itr):
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


def DESdecrypt(filename, key, itr):
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


# AES

def AESencrypt(songname, password):

    print("encrypting")
    print(songname)
    with open(songname, "rb") as file:
        # read all file data
        file_data = file.read()

    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(file_data)

    with open(songname, "wb") as file:
        file.write(cipher_text)

    return {
        'cipher_text': cipher_text,
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def AESdecrypt(songname, password, itr):

    with open(songname, "rb") as file:
        # read all file data
        file_data = file.read()

    # decode the dictionary entries from base64
    salt = b64decode(aestokenlist[itr]['salt'])
    cipher_text = file_data
    nonce = b64decode(aestokenlist[itr]['nonce'])
    tag = b64decode(aestokenlist[itr]['tag'])

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    with open(songname, "wb") as file:
        file.write(decrypted)


# RSA

def EncryptRSA():
    print('RSA Encrypt')
    os.chdir(
        "D:/CLASSROOM/Sem-5/ISAA/Secure_File_Transfer_Using_Random_Encryption_Algorithms-main")

    with open("keys/publicKey.pem", "rb") as file:
        file_data = file.read()
        print(file_data)
        encryptor = PKCS1_OAEP.new(pubKey)
        encrypted = encryptor.encrypt(file_data)
        print("Encrypted File:", binascii.hexlify(encrypted))

    with open("Keys/encrypted.key", "wb") as file:
        file.write(encrypted)


def DecryptRSA():
    os.chdir(
        "D:/CLASSROOM/Sem-5/ISAA/Secure_File_Transfer_Using_Random_Encryption_Algorithms-main")

    with open("keys/encrypted.key", "rb") as file:
        file_data = file.read()
    print(file_data)
    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(file_data)
    print('Decrypted:', decrypted)


#print("Enter your password")
# pwd=input()


# MAIN

def encryptfile():
    print("Encrypting.........................")
    Process_label.configure(text="Encrypting....")
    songli = filesplit()
    print(songli)
    name = name_var.get()
    pwd = passw_var.get()
    globalpwd = pwd

    print("The name is : " + name)
    print("The password is : " + pwd)

    global songlist
    songlist = songli
    print(songlist)

    for i in songlist:
        # a=AESencrypt(i,pwd)

        # DESencrypt(i,key,1)
        a = random.randint(0, 2)
        if a == 1:
            print('DES encrypt \n')
            DESencrypt(i, key, 1)
            aestokenlist.append(0)
            enclist.append('DES')

        if a == 0:
            print('AES encrypt\n')
            b = AESencrypt(i, pwd)
            aestokenlist.append(b)
            enclist.append('AES')

        if a == 2:
            print('3DES encrypt\n')
            DES3encrypt(i, tdes_key, 1)
            aestokenlist.append(2)
            enclist.append('3DES')

        # encrypt(i,key)
        # decrypt(i,key)
        Process_label.configure(text="Encryption complete")
    os.chdir('D:/CLASSROOM/Sem-5/ISAA/project/github/secure_file_system-main')
    EncryptRSA()


def decryptfile():
    DecryptRSA()
    os.chdir('song')
    Process_label.configure(text="Decrypting files!!")
    print(aestokenlist)
    print("Decrypt files?")
    pwd = passwd_var.get()

    print(enclist)
    c = 0

    print(pwd)
    print(songlist)
    for i in songlist:

        print(i)
        if enclist[c] == 'DES':
            DESdecrypt(i, key, 0)
        elif enclist[c] == 'AES':
            AESdecrypt(i, pwd, c)
        else:
            DES3decrypt(i, tdes_key, 2)
        c = c+1
    for i in range(10):
        progress3['value'] = progress['value']+i*10
        root.update_idletasks()
        time.sleep(0.1)
        os.chdir(
            "D:/CLASSROOM/Sem-5/ISAA/Secure_File_Transfer_Using_Random_Encryption_Algorithms-main")
    Process_label.configure(text="Decryption complete")
    EncryptRSA()


def main():
    print("in main")


def submit():

    name = name_var.get()
    filesplit()
    password = passw_var.get()

    print("The name is : " + name)
    print("The password is : " + password)

    name_var.set("")
    passw_var.set("")


# creating a label for
# name using widget Label


name_label = tk.Label(root, text='Username', font=('calibre', 12, 'bold'))


# creating a entry for input
# name using widget Entry
name_entry = tk.Entry(root, textvariable=name_var,
                      font=('calibre', 12, 'normal'))

# creating a label for password
passw_label = tk.Label(root, text='Encryption Password:',
                       font=('calibre', 12, 'bold'))

# creating a entry for password
passw_entry = tk.Entry(root, textvariable=passw_var,
                       font=('calibre', 12, 'normal'), show='*')

# creating a button using the widget
# Button that will call the submit function
enc_btn = tk.Button(root, text='Encrypt', font=(
    'calibre', 12, 'normal'), command=encryptfile)
decr_btn = tk.Button(root, text='Decrypt', font=(
    'calibre', 12, 'normal'), command=openNewWindow)

merge_btn = tk.Button(root, text='Merge', font=(
    'calibre', 12, 'normal'), command=mergefiles)

progress = Progressbar(root, length=100, mode='determinate')
progress2 = Progressbar(root, length=100, mode='determinate')
progress3 = Progressbar(root, length=100, mode='determinate')

# placing the label and entry in
# the required position using grid
# method
Process_label = tk.Label(
    root, text='Welcome to the File System!!!', font=('calibre', 12, 'bold'))

progress.place(x=100)
progress2.place(x=250)
progress3.place(x=400)

label_file_explorer.place(x=250, y=50)

button_explore.place(x=250, y=100)

name_label.place(x=100, y=160)
name_entry.place(x=300, y=160)
passw_label.place(x=100, y=200)
passw_entry.place(x=300, y=200)
enc_btn.place(x=150, y=270)
decr_btn.place(x=350, y=270)
Process_label.place(x=200, y=320)
merge_btn.place(x=450, y=270)


# performing an infinite loop
# for the window to display
root.mainloop()
