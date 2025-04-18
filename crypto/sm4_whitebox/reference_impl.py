#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# 正确性验证，test_pt和test_ct是一直对应的
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import os
from gmssl import sm4, func

n = 8
block_size = 16
plaintexts = []

for i in range(n):
    plaintext = os.urandom(block_size)
    plaintexts.append(plaintext)

with open("test_plaintext", "wb") as plaintext_file:
    for pt in plaintexts:
        plaintext_file.write(pt)

print(f"{n} groups of plaintext written to test_plaintext.")

k = b"samplekey1234567"

with open("test_plaintext", "rb") as plaintext_file:
    pt = plaintext_file.read()

print(len(pt))
if len(pt) % AES.block_size != 0:
    pt = pt[:len(pt) - (len(pt) % AES.block_size)]

# cipher = AES.new(k, AES.MODE_ECB)
# ct = cipher.encrypt(pt)XQ
cipher = sm4.CryptSM4()
cipher.set_key(k, sm4.SM4_ENCRYPT)
ct = cipher.crypt_ecb(pt)  # 加密

ct = ct[:len(pt)]

with open("test_ciphertext", "wb") as ciphertext_file:
    ciphertext_file.write(ct)

print("key:       ", binascii.hexlify(k).decode())
print("plaintext: ", binascii.hexlify(pt).decode())
print("ciphertext:", binascii.hexlify(ct).decode())