#-*- coding:utf-8 -*-
# This program is based on the original work by Alex Biryukov and Aleksei Udovenko.
# Copyright (C) 2018 Alex Biryukov, Aleksei Udovenko
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.

from .op import BitOP
from .node import Node

class BitNode(Node):
    OP = BitOP()

    def make_binary(op):
        def f(a, b):
            if isinstance(b, int): b = a.const(b)
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
