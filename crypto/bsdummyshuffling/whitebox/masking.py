#-*- coding:utf-8 -*-

from whitebox.orderer import Orderer, circuit_inputs
from operator import xor

class MaskingScheme(object):
    NOT = OR = XOR = AND = ZERO = ONE = NotImplemented

    def __init__(self, rand, nshares=2):
        """rand() -> random bit"""
        self.rand = rand
        self.nshares = int(nshares)
        assert nshares >= 2 # maybe 1 is useful for debugging purposes?

    def encode(self, x):
        raise NotImplementedError()

    def decode(self, x):
        raise NotImplementedError()

    def refresh(self, x):
        raise NotImplementedError()

    def __repr__(self):
        return "<MaskingScheme:%s nshares=%d rand=%r>" % (type(self).__name__, self.nshares, self.rand)


class DOM(MaskingScheme):
    def encode(self, s):
        x = [self.rand() for _ in xrange(self.nshares-1)]
        x.append(reduce(xor, x) ^ s)
        return tuple(x)

    def decode(self, x):
        return reduce(xor, x)

    def XOR(self, x, y):
        assert len(x) == len(y) == self.nshares
        return tuple(xx ^ yy for xx, yy in zip(x, y))

    def AND(self, x, y):
        assert len(x) == len(y) == self.nshares
        matrix = [[xx & yy for yy in y] for xx in x]
        for i in xrange(1, self.nshares):
            for j in xrange(i + 1, self.nshares):
                r = self.rand()
                matrix[i][j] ^= r
                matrix[j][i] ^= r
        return tuple(reduce(xor, row) for row in matrix)

    def NOT(self, x):
        assert len(x) == self.nshares
        return (~x[0],) + tuple(x[1:])

    def RANDOM(self):
        # more efficient random shares
        Bit = self.Bit
        return (Bit.const(0),) * (self.nshares - 1) + (Bit(Bit.OP.RANDOM),)

    def refresh(self, x):
        raise NotImplementedError()

class MINQ(MaskingScheme):
    def __init__(self, rand):
        super(MINQ, self).__init__(rand=rand, nshares=3)

    def encode(self, s):
        a = self.rand()
        b = self.rand()
        c = (a & b) ^ s
        return a, b, c

    def decode(self, x):
        return (x[0] & x[1]) ^ x[2]

    def rand3(self):
        return (self.rand(), self.rand(), self.rand())

    def refresh(self, x, rs=None):
        a, b, c = x
        if rs is None:
            rs = self.rand3()
        ra, rb, rc = rs
        ma = ra & (b ^ rc)
        mb = rb & (a ^ rc)
        rmul = (ra ^ rc) & (rb ^ rc)
        rc ^= ma ^ mb ^ rmul
        a ^= ra
        b ^= rb
        c ^= rc
        return a, b, c

    def XOR(self, x, y):
        rxs = ra, rb, rc = self.rand3()
        rys = rd, re, rf = self.rand3()
        a, b, c = self.refresh(x, rs=rxs)
        d, e, f = self.refresh(y, rs=rys)
        x = a ^ d
        y = b ^ e
        ae = a & e
        bd = b & d
        z = c ^ f ^ ae ^ bd
        return x, y, z

    def AND(self, x, y):
        rxs = ra, rb, rc = self.rand3()
        rys = rd, re, rf = self.rand3()
        a, b, c = self.refresh(x, rs=rxs)
        d, e, f = self.refresh(y, rs=rys)

        ma = (b & f) ^ (rc & e)
        md = (c & e) ^ (rf & b)
        x = rf ^ (a & e)
        y = rc ^ (b & d)
        ama = a & ma
        dmd = d & md
        rcrf = rc & rf
        cf = c & f
        z = ama ^ dmd ^ rcrf ^ cf
        return x, y, z

    def NOT(self, x):
        return x[0], x[1], ~x[2]

    def RANDOM(self):
        # more efficient random shares
        Bit = self.Bit
        return Bit.const(0), Bit.const(0), Bit(Bit.OP.RANDOM())



def mask_circuit(ybits, scheme, encode=True, decode=True):
    """
    Mask a given circuit with a given masking scheme.
    WARNING: assumes absence of constant bits (e.g. using OptBitNode)
    """
    scheme.Bit = Bit = type(ybits[0])

    xbits = circuit_inputs(ybits)
    if encode:
        xbits_shares = [scheme.encode(xbit) for xbit in xbits]
    else:
        xbits_shares = [Bit.inputs(xbit.name(), tostr=False) for xbit in xbits]

    shares = dict(zip(xbits, xbits_shares)) # bit -> shares of bit

    for action, bit in Orderer(ybits, quiet=True).compile().code:
        if action != "compute":
            continue

        func = getattr(scheme, Bit.OP.name[bit.op])
        args = [shares[arg] for arg in bit.args]
        res = func(*args)
        shares[bit] = res

    ybits_shares = tuple(shares[ybit] for ybit in ybits)
    if decode:
        return tuple(scheme.decode(yshares) for yshares in ybits_shares)
    else:
        return ybits_shares
