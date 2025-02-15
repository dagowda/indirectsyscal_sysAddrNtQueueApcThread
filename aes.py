

import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib

def AESencrypt(plaintext, key):
    k = hashlib.sha256(KEY).digest()
    print(k)
    iv = 16 * b'\x00'
    print(iv)
    plaintext = pad(plaintext, AES.block_size)
    print(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    print(cipher)
    ciphertext = cipher.encrypt(plaintext)
    print(ciphertext)
    return ciphertext,key

  
def printResult(key, ciphertext):
    print('char AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
    print('unsigned char AESshellcode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
    print(len(ciphertext))
    print(len(key))
try:
    file = open(sys.argv[1], "rb")
    content = file.read()
    print(content)
except:
    print("Usage: .\AES_cryptor.py PAYLOAD_FILE")
    sys.exit()


KEY = urandom(16)
ciphertext, key = AESencrypt(content, KEY)

printResult(KEY,ciphertext)
