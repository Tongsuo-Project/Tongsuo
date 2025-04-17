#-*- coding:utf-8 -*-

from cryptools.py.binary import rol, ror, frombin, tobin
from struct import unpack, pack

u = 0b1111101000100101011000011100110
v = 0b1000111011111001001100001011010
w = 0b1000010010110011111000110111010

t = 0b01010101010101010101010101010101010101010101010101010101010101

z0 = (u | (u << 31))
z1 = (v | (v << 31))
z2 = (u | (u << 31)) ^ t
z3 = (v | (v << 31)) ^ t
z4 = (w | (w << 31)) ^ t

ZSEQ_NR = {
    (16, 4): (z0, 32),

    (24, 3): (z0, 36),
    (24, 4): (z1, 36),

    (32, 3): (z2, 42),
    (32, 4): (z3, 44),

    (48, 2): (z2, 52),
    (48, 3): (z3, 54),

    (64, 2): (z2, 68),
    (64, 3): (z3, 69),
    (64, 4): (z4, 72),
}


def zget(v, n):
    n %= 62
    return (v >> (62 - 1 - n)) & 1

class Simon(object):
    W = None
    ROTS = 8, 1, 2
    INST = {}

    @classmethod
    def nrounds(self, M):
        return ZSEQ_NR[self.W,M][1]

    @classmethod
    def make(self, word_size):
        return self.INST[word_size]()

    def encrypt(self, l, r, ks):
        for k in ks:
            r ^= self.f(l) ^ k
            l, r = r, l
        return l, r

    def f(self, l):
        a = rol(l, self.ROTS[0], self.W)
        b = rol(l, self.ROTS[1], self.W)
        c = rol(l, self.ROTS[2], self.W)
        return (a & b) ^ c

    def key_schedule(self, k, z=None, nr=None):
        k = list(k)
        M = len(k)
        C = (2**self.W-1) ^ 3
        zj = z if z is not None else ZSEQ_NR[self.W,M][0]
        nr = nr if nr is not None else ZSEQ_NR[self.W,M][1]
        for i in xrange(M, nr):
            tmp = rol(k[i-1], -3, self.W)
            if M == 4:
                tmp ^= k[i-3]
            tmp ^= rol(tmp, -1, self.W)

            newk = C
            newk = newk ^ zget(zj, (i-M) % 62)
            newk = newk ^ k[i-M] ^ tmp

            k.append(newk)
        return k

    def key_schedule_linear(self, k, nr=None):
        k = list(k)
        M = len(k)
        nr = nr if nr is not None else ZSEQ_NR[self.W,M][1]
        for i in xrange(M, nr):
            tmp = rol(k[i-1], -3, self.W)
            if M == 4:
                tmp ^= k[i-3]
            tmp ^= rol(tmp, -1, self.W)

            newk = k[i-M] ^ tmp

            k.append(newk)
        return k


class Simon32(Simon):  W = 16
class Simon48(Simon):  W = 24
class Simon64(Simon):  W = 32
class Simon96(Simon):  W = 48
class Simon128(Simon): W = 64

Simon.INST[32/2] = Simon32
Simon.INST[48/2] = Simon48
Simon.INST[64/2] = Simon64
Simon.INST[96/2] = Simon96
Simon.INST[128/2] = Simon128

if __name__ == '__main__':
    def _u(s):
        return tuple(int(w, 16) for w in s.split())

    def test1(ks, pt, ct):
        k = _u(ks)[::-1] # why?!
        l, r = _u(pt)
        WS = len(pt.split()[0])*4

        class SimonTest(Simon):
            W = WS
        s = SimonTest()
        l, r = s.encrypt(l, r, s.key_schedule(k))
        assert (l, r) == _u(ct), ("%04x:%04x vs %04x:%04x" % (l, r, _u(ct)[0], _u(ct)[1]))
        return True

    def test():
        cnt = 0
        # Simon32/64
        cnt += test1("1918 1110 0908 0100", "6565 6877", "c69b e9bb")
        # Simon48/72
        cnt += test1("121110 0a0908 020100", "612067 6e696c", "dae5ac 292cac")
        # Simon48/96
        cnt += test1("1a1918 121110 0a0908 020100", "726963 20646e", "6e06a5 acf156")
        # Simon64/96
        cnt += test1("13121110 0b0a0908 03020100", "6f722067 6e696c63", "5ca2e27f 111a8fc8")
        # Simon64/128
        cnt += test1("1b1a1918 13121110 0b0a0908 03020100", "656b696c 20646e75", "44c8fc20 b9dfa07a")
        # Simon96/96
        cnt += test1("0d0c0b0a0908 050403020100", "2072616c6c69 702065687420", "602807a462b4 69063d8ff082")
        # Simon96/144
        cnt += test1("151413121110 0d0c0b0a0908 050403020100", "746168742074 73756420666f", "ecad1c6c451e 3f59c5db1ae9")
        # Simon128/128
        cnt += test1("0f0e0d0c0b0a0908 0706050403020100", "6373656420737265 6c6c657661727420", "49681b1e1e54fe3f 65aa832af84e0bbc")
        # Simon128/192
        cnt += test1("1716151413121110 0f0e0d0c0b0a0908 0706050403020100", "206572656874206e 6568772065626972", "c4ac61effcdc0d4f 6c9c8d6e2597b85b")
        # Simon128/256
        cnt += test1("1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100", "74206e69206d6f6f 6d69732061207369", "8d2b5579afc8a3a0 3bf72a87efe7b868")

        print "%d tests passed" % cnt

    test()
