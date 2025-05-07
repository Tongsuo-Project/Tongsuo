#-*- coding:utf-8 -*-

def tag_bits(**k):
    for name, bit in list(k.items()):
        bit.meta["tag"] = name

def fake_inputs(**k):
    for name, bit in list(k.items()):
        bit.meta["fake-input"] = name
