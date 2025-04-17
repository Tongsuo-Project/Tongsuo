#!/usr/bin/env pypy
#-*- coding:utf-8 -*-

import os, sys, math
from whitebox.tree.node import OptBitNode as Bit
from whitebox.utils import str2bin, bin2str

NR = 10
# KEY = "MySecretKey!2019"
KEY = "samplekey1234567"
if_enc = 1
if_dummy = 1
slot = 2**1
slice_cnt = 8

from whitebox.ciphers.AES import BitAES
from whitebox.ciphers.SM4 import BitSM4
pt = Bit.inputs("pt", 128)
from whitebox.prng import LFSR, Pool
prng = LFSR(taps=[0, 2, 5, 18, 39, 100, 127],
            state=BitAES(pt, pt[::-1], rounds=2)[0])
rand = Pool(n=128, prng=prng).step

# dummy
def dummy(x, k, if_enc):
    # right_slot
    right_slot = [rand() for _ in range(int(math.log(slot, 2)))]
    # print type(right_slot[0])
    # print(int(math.log(slot, 2)))
    ybits = [Bit.const(0) for _ in range(128)]
    m = [rand() for _ in range(slot-1)]
    m.append(Bit.const(0))
    for i in range(slot-1):
        m[slot-1] ^= m[i]
    for ri in range(slot):
        # ri == right_slot?
        bin_str = bin(ri)[2:].zfill(int(math.log(slot, 2)))
        r = [(Bit.const(0), Bit.const(1))[int(b)] for b in bin_str]
        res = Bit.const(1)
        for i in range(len(right_slot)):
            res &= (Bit.const(1) ^ right_slot[i] ^ r[i])
        
        r = [rand() for _ in range(128)]
        xx = [(r[i]&(~res))^(x[i]&res) for i in range(128)]
        ty = BitSM4(xx, k, if_enc)
        ybits = [ybits[i]^(res&ty[i])^m[ri] for i in range(128)]
    return ybits

if(if_dummy):
    print "dummy shuffle with %d slots" % slot
    ct = dummy(pt, KEY, if_enc)
else:
    # ybits, k10 = AES(xbits, kbits, nr=NR)
    # print(type(str2bin(KEY)), len(str2bin(KEY)))
    # print(type(pt),type(pt[0]),type(KEY))
    ct = BitSM4(pt, KEY, if_enc)

from whitebox.masking import MINQ, DOM, mask_circuit
# choose mask
# ct = mask_circuit(ct, MINQ(rand=rand))
ct = mask_circuit(ct, DOM(rand=rand, nshares=2))

# a) generate WhibOx submission
from whitebox.whibox import whibox_generate
whibox_generate( slice_cnt, ct, "build/code.c", "Ok, world!")

# b) compile circuit to file
from whitebox.serialize import RawSerializer
RawSerializer().serialize_to_file(ct, "circuits/aes10.bin")

# c) compute reference AES to verify correctness
from whitebox.ciphers.AES.aes import encrypt
pt = os.urandom(64)
ct = "".join(encrypt(pt[i:i+16], KEY, nr=NR) for i in xrange(0, len(pt), 16))
open("build/cipher", "w").write(ct)

