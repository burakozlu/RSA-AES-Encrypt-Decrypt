import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import argparse

def aesEncrypt(bitSize,filename):
    try:
        with open(f"{filename}","rb") as file:
            plainData = file.read()
            key = os.urandom(int(bitSize/8))
            with open(f"aeskey{filename}","wb") as aeskeyfile:
                aeskeyfile.write(key)
            iv = os.urandom(16)

            with open(f"aesiv{filename}","wb") as aesivfile:
                aesivfile.write(iv)
        
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            encryptor = cipher.encryptor()
            print("Plain data: " + str(plainData))
            print("key: "+str(key) + "\niv:" + str(iv)+ "\n")
            ct = encryptor.update(plainData) + encryptor.finalize()
            print("Encrypted data: " + str(ct))
            with open(f"AES{filename}","wb") as encfile:
                encfile.write(ct)

    except Exception as ex:
        print("Error : ", ex)    


def aesDecrypt(aeskeyFile,aesivFile,filename):
    try:
        with open(f"{filename}","rb") as file:
            encryptedData = file.read()
            with open(f"{aeskeyFile}","rb") as aeskey:
                key = aeskey.read()
            with open(f"{aesivFile}","rb") as ivkey:
                iv = ivkey.read()
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            decryptor = cipher.decryptor()
            pt = decryptor.update(encryptedData) + decryptor.finalize()
            print("Decrypted Data: " + str(pt))
    except Exception as ex:
        print("Error :",ex)

def encryptRSA(keySize,fileName):
    try:
        with open(f"{fileName}","rb") as file:
            plainData = file.read()
            private_key = rsa.generate_private_key(public_exponent=65537,key_size=keySize)
            public_key = private_key.public_key()
            pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption())
            with open(f"RSAPrivateKey{fileName}.pem","wb") as pemfile:
                pemfile.write(pem)

            ciphertext = public_key.encrypt(plainData,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None))

            with open(f"RSA{fileName}","wb") as encryptedFile:
                encryptedFile.write(ciphertext)
    except Exception as ex:
        print("Error :",ex)           

def decryptRSA(encryptedFileName, pemFileName):
    try:    
        with open(f"{pemFileName}", "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(),password=None)
        with open(f"{encryptedFileName}","rb") as chiperTextFile:
            ciphertext = chiperTextFile.read()
        plaintext = private_key.decrypt(ciphertext,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        print(plaintext)
    except Exception as ex:
        print("Error :",ex)


parser = argparse.ArgumentParser(description="RSA and AES encryption and decryption tool")
parser.add_argument("-a", dest="algorithm",help="Algorithm Type RSA and AES is supported",required=True)
parser.add_argument("-m",dest="method",help="decrypt and encrypt can be used",required=True)
parser.add_argument("-f", dest="fileName", help="",required=True)

parser.add_argument("-s",dest="KeySize")
parser.add_argument("-p",dest="pemFile")

parser.add_argument("-k",dest="aesKeyFile")
parser.add_argument("-iv",dest="aesIvKeyFile")
params = parser.parse_args()

if (params.algorithm == "RSA"):
    if (params.method == "encrypt"):
        encryptRSA(int(params.KeySize),params.fileName)
    elif (params.method == "decrypt"):
        decryptRSA(params.fileName,params.pemFile)
elif (params.algorithm == "AES"):
    if (params.method == "encrypt"):
        aesEncrypt(int(params.KeySize),params.fileName)
    elif (params.method == "decrypt"):
        aesDecrypt(params.aesKeyFile,params.aesIvKeyFile, params.fileName)
