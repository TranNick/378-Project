import os 
import json
#import os.path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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

def RSAKeyGen():
    pemFiles=[]
    filePath=os.getcwd()
    for files in os.listdir(filePath):
        if files.endswith(".pem"):
            pemFiles.append(files)
    if len(pemFiles) > 0:
        for i in range(len(pemFiles)):
            pemFile = open(pemFiles[i], "r")
            headline = pemFile.read()
            pemFile.close()

            if "PRIVATE" in headline:
                privateKeyPath = filePath + "/" + pemFiles[i]
            elif "PUBLIC" in headline:
                publicKeyPath = filePath + "/" + pemFiles[i]
    else:
        privKey = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048, 
            backend=default_backend()
        )
        pubKey = privKey.public_key()
        privateKeyPem=privKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        publicKeyPem=pubKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        privatePem=open("private.pem", 'wb')
        privatePem.write(privateKeyPem)
        privatePem.close()

        publicPem=open('public.pem', 'wb')
        publicPem.write(publicKeyPem)
        privatePem.close()

        privateKeyPath=filePath + "/private.pem"
        publicKeyPath=filePath + "/public.pem"
        
    return privateKeyPath, publicKeyPath

def MyRSAEncrypt(filePath, publicKeyPath, hmacKey):
    (c, iv, tag, key, hmacKey, ext) = myFileEncryptMAC(filePath)
    combinedKey=key+hmacKey
    with open(publicKeyPath, 'rb') as file:
        pubKey=serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )
    RSACipher=pubKey.encrypt(
        combinedKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return (RSACipher, c, iv, tag, ext)
def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_path, filePath):
    with open(RSA_Privatekey_path, 'rb') as file:
        privKey=serialization.load_pem_private_key(
            file.read(),
            backend=default_backend()
        )
        combinedKeys=privKey.decrypt(
            RSACipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        plainText=myFileDecryptMAC(filePath, C, IV, combinedKeys[:32], combinedKeys[32:64], tag)
    
    return plainText

def main():
    key=os.urandom(32)
    hmacKey=os.urandom(32)
#     print("Original message: ", message)
#     print("\nNow encrypting...\n")
#     (cipherText, iv)=myEncrypt(key, message)
#     print("Ciphertext: ", cipherText)
#     print("\nNow decrypting...\n")
#     print("Plaintext: ", myDecrypt(key, iv, cipherText))
#     print("\nEncrypting file contents...")
#     (cipherText, iv, key, ext)=myFileEncrypt(path)
#     print("\nDecrypted file contents: ", myFileDecrypt(path, cipherText, iv, key))

#     print("\nTesting HMAC\n")
#     (C, IV, h)=myEncryptMAC(key, message, hmacKey)
#     print("Ciphertext ", C)
#    # print(h)
#     ogMessage=myDecryptMAC(key, IV, C, hmacKey, h)
#     (C, IV, key, ext, tag)=myFileEncryptMAC(path, hmacKey)
#     print("CipherText: {}\nIV: {}\nkey: {}\nextension: {}\n" .format(C, IV, key, ext))
#     fileText=myFileDecryptMAC(path, C, IV, key, hmacKey, tag)
#     print(fileText)
    (privatePath, publicPath) = RSAKeyGen()
    print("private path ", privatePath)
    print("public path", publicPath)
    (RSACipher, C, IV, ext) = MyRSAEncrypt(path, publicPath, hmacKey)
    text=MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_path, filePath)
    print("plaintext: ", text)
main()

