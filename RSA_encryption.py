from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

keyPair = RSA.generate(3072)

pubKey = keyPair.publickey()
print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
print(pubKeyPEM.decode('ascii'))

print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
print(privKeyPEM.decode('ascii'))


msg = b'A message for encryption'
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted:", binascii.hexlify(encrypted))

decryptor = PKCS1_OAEP.new(keyPair)
decrypted = decryptor.decrypt(encrypted)
print('Decrypted:', decrypted)


# print('RSA Encrypt')
# with open("Keys/publicKey.pem", "rb") as file:
#     file_data = file.read()
#     print(file_data)
#     encryptor = PKCS1_OAEP.new(pubKey)
#     encrypted = encryptor.encrypt(file_data)
#     print("Encrypted File:", binascii.hexlify(encrypted))


# print('RSA Decrypt')
# with open("Keys/privateKey.pem", "rb") as file:
#     file_data = file.read()
#     print(file_data)
#     decryptor = PKCS1_OAEP.new(keyPair)
#     decrypted = decryptor.decrypt(encrypted)
#     print('Decrypted:', decrypted)


def EncryptRSA():
    print('RSA Encrypt')
    with open("keys/publicKey.pem", "rb") as file:
        file_data = file.read()
        print(file_data)
        encryptor = PKCS1_OAEP.new(pubKey)
        encrypted = encryptor.encrypt(file_data)
        print("Encrypted File:", binascii.hexlify(encrypted))

    with open("Keys/encrypted.key", "wb") as file:
        file.write(encrypted)


def DecryptRSA():
    with open("keys/encrypted.key", "rb") as file:
        file_data = file.read()
    print(file_data)
    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(file_data)
    print('Decrypted:', decrypted)


EncryptRSA()
DecryptRSA()
