#!/usr/bin/env python3
#-*- coding:utf-8 -*-

# This program is based on the original work by Alex Biryukov and Aleksei Udovenko.
# Copyright (C) 2018 Alex Biryukov, Aleksei Udovenko
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.

import os, math, random
from whitebox.tree.node import OptBitNode as Bit
from whitebox.ciphers.SM4 import BitSM4, randSM4
from whitebox.prng import LFSR, Pool
from whitebox.masking import MINQ, DOM, mask_circuit
from whitebox.whibox import whibox_generate

KEY = "samplekey1234567"
if_dummy = 1
slot = 2**1
slice_cnt = 1
# 随机参数
rp=[random.randint(0, 255) for _ in range(16)]


for if_enc in range(2):
    pt = Bit.inputs("pt", 128)
    rp = Bit.inputs("rp", 128)
    prng = LFSR(taps=[0, 2, 5, 18, 39, 100, 127], state=randSM4(pt,rp))
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
        print("dummy shuffle with %d slots" % slot)
        ct = dummy(pt, KEY, if_enc)
    else:
        ct = BitSM4(pt, KEY, if_enc)

    # choose mask
    # ct = mask_circuit(ct, MINQ(rand=rand))
    ct = mask_circuit(ct, DOM(rand=rand, nshares=2))

    # generate Whibox submission
    script_dir = os.path.dirname(os.path.abspath(__file__)) 
    file_path = os.path.join(script_dir, "bsdummyshuffling.c")
    whibox_generate(if_enc, slice_cnt, ct, file_path)
