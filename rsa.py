import os 
import json
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as textPadding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

testpath='/home/nick/Downloads/378/text.txt'
#directory = '/home/nick/Downloads/378/asdf'
projectPath = '/home/nick/Downloads/378/Project378'

def RSAKeyGen():
    pemFiles=[]
    filePath=os.getcwd()
    for files in os.listdir(filePath):
        if files.lower().endswith(".pem"):
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
            format=serialization.PrivateFormat.TraditionalOpenSSL,
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

def myEncrypt(key, text):
    if len(key)<32:
        print("The key must be 32 bytes")
        return "Error"
    else:
        iv=os.urandom(16)

        padder=textPadding.PKCS7(128).padder()
        paddedText=padder.update(text) 
        paddedText+=padder.finalize()

        cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encrypt=cipher.encryptor()
        cipherText=encrypt.update(paddedText) + encrypt.finalize()

        return (cipherText, iv)

def myFileEncryptMAC(path):
    key=os.urandom(32)
    hmacKey=os.urandom(32)
    iv=os.urandom(16)

    with open(path, 'rb') as file:
        fileText=file.read()

    ext=os.path.splitext(path)[1]
    (fileCipher, iv)=myEncrypt(key, fileText)
    returnCipher=fileCipher
    h=hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
    h.update(returnCipher)

    wr=open(path, 'wb')
    wr.write(fileCipher)
    wr.close()

    return (returnCipher, iv, h.finalize(), key, hmacKey, ext)

def myFileDecryptMAC(path, cipherText, iv, key, hmacKey, h):
    hTag=hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
    hTag.update(cipherText)
    hTag.verify(h)

    # with open(path, 'rb') as file:
    #    fileText=file.read()
    # print("\nReading Encrypted Text from File: ", fileText)

    filePlain=myDecryptMAC(key, iv, cipherText, hmacKey, h)
    wr=open(path, 'wb')
    wr.write(filePlain)
    wr.close()   

    return (filePlain)

def myFileDecryptMAC(path, cipherText, iv, key, hmacKey, h):
    hTag=hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
    hTag.update(cipherText)
    hTag.verify(h)

    # with open(path, 'rb') as file:
    #    fileText=file.read()
    # print("\nReading Encrypted Text from File: ", fileText)

    filePlain=myDecryptMAC(key, iv, cipherText, hmacKey, h)
    wr=open(path, 'wb')
    wr.write(filePlain)
    wr.close()   

    return (filePlain)

def myDecryptMAC(key, iv, cipherText, hmacKey, h):
    hTag=hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
    hTag.update(cipherText)
    hTag.verify(h)

    cipher=Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypt=cipher.decryptor()
    cipherText=decrypt.update(cipherText) + decrypt.finalize()

    unpadder=textPadding.PKCS7(128).unpadder()
    unpaddedText=unpadder.update(cipherText) + unpadder.finalize()

    return unpaddedText

def MyRSAEncrypt(filePath, publicKeyPath):
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
            password=None,
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

def EncryptAll(directory, publicPath):
    for root, dirs, filesToEncrypt in os.walk(directory):
        for files in filesToEncrypt:
            if "rsa.py" not in files and "public.pem" not in files and "private.pem" not in files  and not files.endswith(".json") and not files.endswith(".git"):       
                fileDirectory = root + "/" + files
                (RSACipher, c, iv, tag, ext)=MyRSAEncrypt(fileDirectory, publicPath)

                fileName=os.path.splitext(fileDirectory)[0] +".json"

               # btsCiphertext = base64.encodebytes(c)
                encodedCiphertext = base64.encodebytes(c).decode('ascii')
               # btsEncryptedKeys = base64.encodebytes(RSACipher)
                encodedEncryptedKeys = base64.encodebytes(RSACipher).decode('ascii')
                #btsHMACTag = base64.encodebytes(tag)
                encodedHMACTag = base64.encodebytes(tag).decode('ascii')
                #btsIV = base64.encodebytes(iv)
                encodedIV = base64.encodebytes(iv).decode('ascii')

                jsonObj={"RSA Cipher: " : encodedEncryptedKeys, "Ciphertext: " : encodedCiphertext, "IV: " : encodedIV, "Tag: " : encodedHMACTag, "Extension: " : ext}
                
                jsonFile=json.dumps(jsonObj)
                jsonOutput=open(fileName, 'w')
                jsonOutput.write(jsonFile)
                os.remove(directory+"/"+files)

def DecryptAll(directory, privatePath):
    #os.chdir(directory)
    for root, dirs, filesToDecrypt in os.walk(directory):
        for files in filesToDecrypt:
            if files.endswith(".json"):
                jsonInput = open(files, "r")
                jsonData = jsonInput.read()

                jsonObj = json.loads(jsonData)

                #stbCiphertext = jsonObj["Ciphertext: "].encode('ascii')
                decodedCiphertext = base64.decodebytes(stbCiphertext)
                #stbEncryptedKeys = jsonObj["RSA Cipher: "].encode('ascii')
                decodedEncryptedKeys = base64.decodebytes(stbEncryptedKeys)
                #stbHMACTag = jsonObj["Tag: "].encode('ascii')
                decodedHMACTag = base64.decodebytes(stbHMACTag)
                #stbIV = jsonObj["IV: "].encode('ascii')
                decodedIV = base64.decodebytes(stbIV)
                ext = jsonObj["Extension: "]

                plaintext = MyRSADecrypt(decodedEncryptedKeys, decodedCiphertext, decodedIV, decodedHMACTag, ext, privatePath, files)
                filePath=os.path.splitext(root+"/"+files)[0] + ext
                fileOut=open(filePath, 'wb')
                fileOut.write(plaintext)
                os.remove(files)
        # print(os.path.dirname(directory))
        # print(directory)
        # print(files)
    #print("hello")

def main():
    (privatePath, publicPath) = RSAKeyGen()
    print("private path ", privatePath)
    print("public path", publicPath)
    # (RSACipher, C, IV, tag, ext) = MyRSAEncrypt(path, publicPath)
    # text=MyRSADecrypt(RSACipher, C, IV, tag, ext, privatePath, path)
    path1=os.getcwd()
    print(path1)
    # EncryptAll(path1, publicPath)
    # x = input("Enter something to continue: ")
    # DecryptAll(path1, privatePath)

    
main()