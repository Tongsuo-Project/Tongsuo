#-*- coding:utf-8 -*-

from cryptools.py.anf.symbolic import Bit

def compute_anfs(bit):
    if bit.is_input():
        bit.meta["anf"] = Bit(bit.name())
        return

    if bit.is_const():
        bit.meta["anf"] = Bit(bit.value())
        return

    TreeBit = bit.__class__
    res = []
    for sub in bit.args:
        if isinstance(sub, TreeBit) and "anf" not in sub.meta:
            compute_anfs(sub)
        res.append(sub.meta["anf"])
    bit.meta["anf"] = bit.OP.eval(bit.op, res)
    # print "BIT", bit, "ANF", bit.meta["anf"]
