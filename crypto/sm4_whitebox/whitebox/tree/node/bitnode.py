#-*- coding:utf-8 -*-

from op import BitOP
from node import Node

class BitNode(Node):
    OP = BitOP()

    def make_binary(op):
        def f(a, b):
            if isinstance(b, (int, long)): b = a.const(b)
            return a.__class__(op, a, b)
        return f

    Xor = __xor__ = __rxor__ = make_binary(OP.XOR)
    And = __and__ = __rand__ = make_binary(OP.AND)
    Or = __or__ = __ror__ = make_binary(OP.OR)
    del make_binary

    def __invert__(self):
        return self.new(self.OP.NOT, self)
    Not = __invert__

    def is_const(self):
        return self.op in (self.OP.ONE, self.OP.ZERO)

    def value(self):
        assert self.op in (self.OP.ONE, self.OP.ZERO)
        return int(self.op == self.OP.ONE)

    @classmethod
    def const(cls, v):
        return cls.new(cls.OP.ONE) if int(v) else cls.new(cls.OP.ZERO)

    @classmethod
    def consts(cls, vs):
        return [cls.const(v) for v in vs]
