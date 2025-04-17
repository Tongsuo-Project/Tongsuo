#!/usr/bin/env python2
#-*- coding:utf-8 -*-

from random import choice

from struct import pack

# preserve the circuit completely,
# from whitebox.tree.node import BitNode as Bit
# or do some trivial optimizations?
from whitebox.tree.node import OptBitNode as Bit

from whitebox.orderer import Orderer, circuit_filter_op
from whitebox.utils import str2bin
from whitebox.masking import *

from whitebox.prng import LFSR

from whitebox.ciphers.AES import BitAES

NR = 2
print NR, "rounds"

KEY = "ABCDxyzwUIOPvbnm"
KEY_BITS = Bit.consts(str2bin(KEY))

def check(ct):
    co = Orderer(ct).compile()
    print "rand bits:", len(list(circuit_filter_op(ct, Bit.OP.RANDOM)))

pt = Bit.inputs("pt", 128)
ct, k10 = BitAES(pt, KEY_BITS, rounds=NR)
check(ct)

if 1:
    # pseudorandomness (via a small pool for efficiency)
    from whitebox.prng import LFSR, Pool
    rand = Pool(n=1000, prng=LFSR(taps=[0, 2, 5, 18, 39, 100, 127], state=pt)).step
else:
    # simulated randomness
    rand = lambda: Bit(Bit.OP.RANDOM)

minq = MINQ(rand=rand)
lin3 = DOM(rand=rand, nshares=2)

for scheme in (minq, lin3):
# for scheme in (lin3,):
    print scheme
    # ct = mask_circuit(ct, scheme)
    # check(ct)
    print

print "Generating final code"
code = []
co = Orderer(ct).compile()

from whitebox.serialize import RawSerializer

RS = RawSerializer()
header, opcodes = RS.serialize(co)
print "Memory usage:", RS.ram_size

# a) for local testing, tracing, analysis, etc.
header_data = "".join(header)
opcodes_data = "".join(opcodes)
with open("circuits/test.bin", "w") as f:
    f.write(header_data)
    f.write(opcodes_data)

# b) for whibox submission
from whitebox.templates import Template, encode_bytes
code = Template("whibox2019.c").subs(
    input_addr=RS.input_addr,
    output_addr=RS.output_addr,
    opcodes_encoded='"%s"' %  encode_bytes(opcodes_data),
    ram_size=RS.ram_size,
    num_opcodes=len(opcodes),
)
with open("build/submit.c", "w") as f:
    f.write(code)

# some stats
print "Opcodes size: %.2f megabytes" % (len(opcodes_data) / 2.0**20),
print ";", len(opcodes), "operations"
# print "Encoded opcodes: %.2f megabytes" % (len(opcodes_encoded) / 2.0**20)
print "Total submission size: %.2f megabytes" % (len(code) / 2.0**20)

# generate reference ciphertexts for validation
from AES.aes import encrypt
pt = open("plain").read()
ct = "".join(encrypt(pt[i:i+16], KEY, nr=NR) for i in xrange(0, len(pt), 16))
open("cipher", "w").write(ct)
