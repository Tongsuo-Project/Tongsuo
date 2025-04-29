#-*- coding:utf-8 -*-

from op import BitOP
from bitnode import BitNode

class OptBitNode(BitNode):
    OP = BitOP()

    CANCEL_DOUBLE_NOT = True
    SINGLETON_CONSTANTS = True
    PRECOMPUTE_CONSTANTS = True
    PRECOMPUTE_ANNIHILATION = True
    CANCEL_NEUTRAL = True
    XOR1_TO_NEGATION = True

    _ONE = _ZERO = None

    # UNARY
    def __invert__(self):
        if self.CANCEL_DOUBLE_NOT and self.op == self.OP.NOT:
            return self.args[0]
        if self.PRECOMPUTE_CONSTANTS and self.is_const():
            return self.const(self.value() ^ 1)
        return self.new(self.OP.NOT, self)
    Not = __invert__

    # BINARY
    def make_binary(op):
        def f(a, b):
            if isinstance(b, (int, long)): b = a.const(b)
            a0, b0 = a, b

            # ensure b is constant if at least one is constant
            if a.is_const(): a, b = b, a
            if not b.is_const(): return a.new(op, a0, b0)

            if a.PRECOMPUTE_CONSTANTS:
                # both consts
                if a.is_const() and b.is_const():
                    return a.const(a.OP.eval(op, (a.value(), b.value())))

            if a.PRECOMPUTE_ANNIHILATION:
                if b.is_const():
                    if op == a.OP.AND and b.value() == 0: return a.const(0)
                    if op == a.OP.OR  and b.value() == 1: return a.const(1)

            if a.CANCEL_NEUTRAL:
                if b.is_const():
                    if op == a.OP.AND and b.value() == 1: return a
                    if op == a.OP.OR  and b.value() == 0: return a
                    if op == a.OP.XOR and b.value() == 0: return a

            if a.XOR1_TO_NEGATION:
                if op == a.OP.XOR and b.value() == 1: return ~a

            return a.new(op, a0, b0)
        return f

    Xor = __xor__ = __rxor__ = make_binary(OP.XOR)
    And = __and__ = __rand__ = make_binary(OP.AND)
    Or = __or__ = __ror__ = make_binary(OP.OR)
    del make_binary

    # const optimizations
    @classmethod
    def const(cls, v):
        if cls.SINGLETON_CONSTANTS:
            if cls._ONE is None:
                cls._ZERO = cls(cls.OP.ZERO)
                cls._ONE = cls(cls.OP.ONE)
            return cls._ONE if int(v) else cls._ZERO
        else:
            return cls(cls.OP.ONE) if int(v) else cls(cls.OP.ZERO)


if __name__ == '__main__':
    Bit = OptBitNode
    x = Bit.inputs("x", 8, tostr=True)
    y = ~(x[0] ^ x[1] & x[2]) ^ 1
    print "expr", y
    print "flattened:"
    for v in y.flatten():
        print "   ", v

    def updict(d):
        # return {("x", k): v for k, v in d.items()}
        return {("x%d" % k): v for k, v in d.items()}

    y = ~(x[0] ^ x[1] & x[2])
    print "1 =?", y.eval(updict({0: 1, 1: 1, 2: 1}))
    y = (x[0] ^ x[1] & x[2])
    print "0 =?", y.eval(updict({0: 1, 1: 1, 2: 1}))
