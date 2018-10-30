import os 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac

#backend=default_backend()
message=b"a secret message for padding "
path='/home/nick/Downloads/378/text.txt'

def myEncrypt(key, text):
    if len(key)<32:
        print("The key must be 32 bytes")
        return "Error"
    else:
        iv=os.urandom(16)

        padder=padding.PKCS7(128).padder()
        paddedText=padder.update(text) 
        paddedText+=padder.finalize()

        cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encrypt=cipher.encryptor()
        cipherText=encrypt.update(paddedText) + encrypt.finalize()

        return (cipherText, iv)

def myDecrypt(key, iv, cipherText):
    cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypt=cipher.decryptor()
    cipherText=decrypt.update(cipherText) + decrypt.finalize()

    unpadder=padding.PKCS7(128).unpadder()
    unpaddedText=unpadder.update(cipherText) + unpadder.finalize()

    return unpaddedText

def myFileEncrypt(path):
    with open(path, 'rb') as file:
        fileText=file.read()
    #print("\nOriginal Text: ", fileText)

    key=os.urandom(32)
    ext=os.path.splitext(path)[1]
    (fileCipher, iv)=myEncrypt(key, fileText)
    returnCipher=fileCipher

    print("\nWriting encrypted text to file...")
    wr=open(path, 'wb')
    wr.write(fileCipher)
    wr.close()

    return (returnCipher, iv, key, ext) 

def myFileDecrypt(path, cipherText, iv, key):
    with open(path, 'rb') as file:
       fileText=file.read()
    #print("\nReading Encrypted Text from File: ", fileText)

    filePlain=myDecrypt(key, iv, cipherText)
    wr=open(path, 'wb')
    wr.write(filePlain)
    wr.close()   

    return (filePlain)

def myEncryptMAC(key, text, hmacKey):
    if len(key)<32:
        print("The key must be 32 bytes")
        return "Error"
    else:
        iv=os.urandom(16)

        padder=padding.PKCS7(128).padder()
        paddedText=padder.update(text) 
        paddedText+=padder.finalize()

        cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encrypt=cipher.encryptor()
        cipherText=encrypt.update(paddedText) + encrypt.finalize()

        h=hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
        h.update(cipherText)

        return (cipherText, iv, h.finalize())       

def myDecryptMAC(key, iv, cipherText, hmacKey, h):
    hTag=hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
    hTag.update(cipherText)
    hTag.verify(h)

    cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypt=cipher.decryptor()
    cipherText=decrypt.update(cipherText) + decrypt.finalize()

    unpadder=padding.PKCS7(128).unpadder()
    unpaddedText=unpadder.update(cipherText) + unpadder.finalize()

    return unpaddedText

def myFileEncryptMAC(path, hmacKey):
    with open(path, 'rb') as file:
        fileText=file.read()
    print("\nOriginal Text: ", fileText)

    key=os.urandom(32)
    ext=os.path.splitext(path)[1]
    (fileCipher, iv)=myEncrypt(key, fileText)
    returnCipher=fileCipher
    h=hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
    h.update(returnCipher)

    print("\nWriting encrypted text to file...")
    wr=open(path, 'wb')
    wr.write(fileCipher)
    wr.close()

    return (returnCipher, iv, key, ext, h.finalize())

def myFileDecryptMAC(path, cipherText, iv, key, hmacKey, h):
    hTag=hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
    hTag.update(cipherText)
    hTag.verify(h)

    with open(path, 'rb') as file:
       fileText=file.read()
    print("\nReading Encrypted Text from File: ", fileText)

    filePlain=myDecryptMAC(key, iv, cipherText, hmacKey, h)
    wr=open(path, 'wb')
    wr.write(filePlain)
    wr.close()   

    return (filePlain)
        
def main():
    key=os.urandom(32)
    hmacKey=os.urandom(32)
    print("Original message: ", message)
    print("\nNow encrypting...\n")
    (cipherText, iv)=myEncrypt(key, message)
    print("Ciphertext: ", cipherText)
    print("\nNow decrypting...\n")
    print("Plaintext: ", myDecrypt(key, iv, cipherText))
    print("\nEncrypting file contents...")
    (cipherText, iv, key, ext)=myFileEncrypt(path)
    print("\nDecrypted file contents: ", myFileDecrypt(path, cipherText, iv, key))

    print("\nTesting HMAC\n")
    (C, IV, h)=myEncryptMAC(key, message, hmacKey)
    print("Ciphertext ", C)
   # print(h)
    ogMessage=myDecryptMAC(key, IV, C, hmacKey, h)
    (C, IV, key, ext, hFile)=myFileEncryptMAC(path, hmacKey)
    print("CipherText: {}\nIV: {}\nkey: {}\nextension: {}\n" .format(C, IV, key, ext))
    fileText=myFileDecryptMAC(path, C, IV, key, hmacKey, hFile)
    print(fileText)


main()

