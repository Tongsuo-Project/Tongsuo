#-*- coding:utf-8 -*-

def str2bin(s):
    return map(int, "".join(bin(ord(c))[2:].zfill(8) for c in s))

def bin2str(b):
    assert len(b) % 8 == 0
    v = int("".join(map(str, b)), 2)
    v = ("%x" % v).zfill(len(b) / 4)
    return v.decode("hex")
