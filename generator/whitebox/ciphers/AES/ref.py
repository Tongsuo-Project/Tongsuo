#-*- coding:utf-8 -*-

from pyaes import *

def encrypt(plain, key, nr=10):
    ks = ks_expand(map(ord, key))
    s = transpose(map(ord, plain))
    for r in xrange(nr):
        s = AddRoundKey(s, ks[r])
        s = SubBytes(s)
        s = ShiftRows(s)
        if r < nr - 1:
            s = MixColumns(s)
    s = AddRoundKey(s, ks[nr])
    return "".join(map(chr, transpose(s)))
