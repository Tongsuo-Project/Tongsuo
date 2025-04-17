#-*- coding:utf-8 -*-

'''
Based on

D. Canright. A Very Compact S-Box for AES. In J. R. Rao and B. Sunar, editors,
Cryptographic Hardware and Embedded Systems – CHES 2005, Proceedings, volume 3659
of Lecture Notes in Computer Science, pages 441–455. Springer, 2005.
'''

def GF_SQ_2(A): return A[1], A[0]
def GF_SCLW_2(A): return A[1], A[1] ^ A[0]
def GF_SCLW2_2(A): return A[1] ^ A[0], A[0]

# To support bitsliced calls.
# Otherwise just do & 1 on bits
MASK = 2**64-1 # 0xffffffffffffffff
def Not(x):
    return MASK^x

def GF_MULS_2(A, ab, B, cd):
    abcd = (ab & cd)
    p = ((A[1] & B[1])) ^ abcd
    q = ((A[0] & B[0])) ^ abcd
    return q, p

def GF_MULS_SCL_2(A, ab, B, cd):
    t = (A[0] & B[0])
    p = ((ab & cd)) ^ t
    q = ((A[1] & B[1])) ^ t
    return q, p

def XOR_LIST(a, b):
    return [a ^ b for a, b in zip(a, b)]

def NotOr(a, b):
    # return Not(a | b)
    return Not(a) & Not(b)

def GF_INV_4(A):
    a = A[2:4]
    b = A[0:2]
    sa = a[1] ^ a[0]
    sb = b[1] ^ b[0]

    ab = GF_MULS_2(a, sa, b, sb)
    ab2 = GF_SQ_2(XOR_LIST(a, b))
    ab2N = GF_SCLW2_2(ab2)
    d = GF_SQ_2(XOR_LIST(ab, ab2N))

    c = [
        NotOr(sa, sb) ^ (Not(a[0] & b[0])),
        NotOr(a[1], b[1]) ^ (Not(sa & sb)),
    ]

    sd = d[1] ^ d[0]
    p = GF_MULS_2(d, sd, b, sb)
    q = GF_MULS_2(d, sd, a, sa)
    return q + p

def GF_SQ_SCL_4(A):
    a = A[2:4]
    b = A[0:2]
    ab2 = GF_SQ_2(a ^ b)
    b2 = GF_SQ_2(b)
    b2N2 = GF_SCLW_2(b2)
    return b2N2 + ab2

def GF_MULS_4(A, a, Al, Ah, aa, B, b, Bl, Bh, bb):
    ph = GF_MULS_2(A[2:4], Ah, B[2:4], Bh)
    pl = GF_MULS_2(A[0:2], Al, B[0:2], Bl)
    p = GF_MULS_SCL_2(a, aa, b, bb)
    return XOR_LIST(pl, p) + XOR_LIST(ph, p) #(pl ^ p), (ph ^ p)

def GF_INV_8(A):
    a = A[4:8]
    b = A[0:4]
    sa = XOR_LIST(a[2:4], a[0:2])
    sb = XOR_LIST(b[2:4], b[0:2])
    al = a[1] ^ a[0]
    ah = a[3] ^ a[2]
    aa = sa[1] ^ sa[0]
    bl = b[1] ^ b[0]
    bh = b[3] ^ b[2]
    bb = sb[1] ^ sb[0]

    c1 = (ah & bh)
    c2 = (sa[0] & sb[0])
    c3 = (aa & bb)

    c = [
        (NotOr(a[0] , b[0] ) ^ ((al & bl))) ^ ((sa[1] & sb[1])) ^ Not(c2), #0
        (NotOr(al   , bl   ) ^ (Not(a[1] & b[1]))) ^ c2 ^ c3 , #1
        (NotOr(sa[1], sb[1]) ^ (Not(a[2] & b[2]))) ^ c1 ^ c2 , #2
        (NotOr(sa[0], sb[0]) ^ (Not(a[3] & b[3]))) ^ c1 ^ c3 , #3
    ]
    d = GF_INV_4(c)

    sd = XOR_LIST(d[2:4], d[0:2])
    dl = d[1] ^ d[0]
    dh = d[3] ^ d[2]
    dd = sd[1] ^ sd[0]
    p = GF_MULS_4(d, sd, dl, dh, dd, b, sb, bl, bh, bb)
    q = GF_MULS_4(d, sd, dl, dh, dd, a, sa, al, ah, aa)
    return q + p

def MUX21I(A, B, s): #return ((~A & s) ^ (~B & ~s)
    return Not(A if s else B)

def SELECT_NOT_8( A, B, s):
    Q = [None] * 8
    for i in xrange(8):
        Q[i] = MUX21I(A[i], B[i], s)
    return Q

def bSbox(A, encrypt):
    R1 = A[7] ^ A[5]
    R2 = A[7] ^ Not(A[4])
    R3 = A[6] ^ A[0]
    R4 = A[5] ^ Not(R3)
    R5 = A[4] ^ R4
    R6 = A[3] ^ A[0]
    R7 = A[2] ^ R1
    R8 = A[1] ^ R3
    R9 = A[3] ^ R8

    B = [None] * 8
    B[7] = R7 ^ Not(R8)
    B[6] = R5
    B[5] = A[1] ^ R4
    B[4] = R1 ^ Not(R3)
    B[3] = A[1]^ R2 ^ R6
    B[2] = Not( A[0])
    B[1] = R4
    B[0] = A[2] ^ Not(R9)

    Y = [None] * 8
    Y[7] = R2
    Y[6] = A[4] ^ R8
    Y[5] = A[6] ^ A[4]
    Y[4] = R9
    Y[3] = A[6] ^ Not(R2)
    Y[2] = R7
    Y[1] = A[4] ^ R6
    Y[0] = A[1] ^ R5

    Z = SELECT_NOT_8(B, Y, encrypt)
    C = GF_INV_8(Z)

    T1 = C[7] ^ C[3]
    T2 = C[6] ^ C[4]
    T3 = C[6] ^ C[0]
    T4 = C[5] ^ Not(C[3])
    T5 = C[5] ^ Not(T1)
    T6 = C[5] ^ Not(C[1])
    T7 = C[4] ^ Not(T6)
    T8 = C[2] ^ T4
    T9 = C[1] ^ T2
    T10 = T3 ^ T5

    D = [None] * 8
    D[7] = T4
    D[6] = T1
    D[5] = T3
    D[4] = T5
    D[3] = T2 ^ T5
    D[2] = T3 ^ T8
    D[1] = T7
    D[0] = T9

    X = [None] * 8
    X[7] = C[4] ^ Not(C[1])
    X[6] = C[1] ^ T10
    X[5] = C[2] ^ T10
    X[4] = C[6] ^ Not(C[1])
    X[3] = T8 ^ T9
    X[2] = C[7] ^ Not(T7)
    X[1] = T6
    X[0] = Not(C[2])
    return SELECT_NOT_8(D, X, encrypt)


def bitSbox(A, inverse=False):
    res = bSbox(A[::-1], encrypt=1-inverse)[::-1]
    return res

if __name__ == '__main__':
    tobin = lambda x, n: tuple(map(int, bin(x).lstrip("0b").rjust(n, "0")))
    frombin = lambda v: int("".join(map(str, v)), 2 )

    sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]

    for x in xrange(256):
        xv = list(tobin(x, 8))

        # s-box check
        yv = bitSbox(xv)
        y = frombin(v & 1 for v in yv)
        assert sbox[x] == y, (x, y, sbox[x])

        # check inverse is good
        assert xv == bitSbox(yv, inverse=True)

        print x, sbox[x], y

    print "Sbox test OK"
