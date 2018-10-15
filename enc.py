import os 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

backend=default_backend()
message=b"a secret message for padding "
key=os.urandom(32)
iv=os.urandom(16)
path='/home/nick/Downloads/378/text.txt'

def myEncryptor(text):
    padder=padding.PKCS7(128).padder()
    paddedText=padder.update(text) 
    paddedText+=padder.finalize()
    cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encrypt=cipher.encryptor()
    cipherText=encrypt.update(paddedText) + encrypt.finalize()
    print("Padded text: ", paddedText)
    return cipherText

def myDecryptor(cipherText):
    cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decrypt=cipher.decryptor()
    cipherText=decrypt.update(cipherText) + decrypt.finalize()
    unpadder=padding.PKCS7(128).unpadder()
    unpaddedText=unpadder.update(cipherText) + unpadder.finalize()
    return unpaddedText

def myFileEncryptor():
    with open(path, 'r') as file:
        fileText=file.read()
    print("\nOriginal Text: ", fileText)
    fileTextBytes=fileText.encode()
    fileCipher=myEncryptor(fileTextBytes)
    returnCipher=fileCipher
    print("\nWriting encrypted text to file...")
    wr=open(path, 'wb')
    #wr=open('/home/nick/Downloads/378/cipher.txt', 'wb')
    wr.write(fileCipher)
    wr.close()
    return (returnCipher)

def myFileDecryptor():
    with open(path, 'rb') as file:
       fileText=file.read()
    # with open('/home/nick/Downloads/378/cipher.txt', 'rb') as file:
    #     fileText=file.read()
    print("\nReading Encrypted Text from File: ", fileText)
    filePlain=myDecryptor(fileText)
    wr=open(path, 'w')
    wr.write(filePlain.decode())
    wr.close()   
    return (filePlain)
        
def main():
    print("Original message: ", message)
    print("\nNow encrypting...\n")
    cipherText=myEncryptor(message)
    print("Ciphertext: ", cipherText)
    print("\nNow decrypting...\n")
    myDecryptor(cipherText)
    print("Plaintext: ", myDecryptor(cipherText))
    print("\nEncrypting file contents...")
    myFileEncryptor()
    print("\nDecrypted file contents: ", myFileDecryptor())

main()

