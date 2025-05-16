#-*- coding:utf-8 -*-
# This program is based on the original work by Alex Biryukov and Aleksei Udovenko.
# Copyright (C) 2018 Alex Biryukov, Aleksei Udovenko
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.

import sys
import operator
from random import randint

class OP(object):
    OPS = {}

    def __init__(self):
        self.free_id = 10 # to avoid bugs, e.g. Bit(0) will raise error (for const need to use Bit.const(0))

        self.name = {}
        self.arity = {}

        self.operator = {}
        self.symbol = {}
        self.symmetric = {}

        for name, data in self.OPS:
            self.add_op(name, data)

    def add_op(self, name, data):
        name = name.upper()
        opnum = data.get("id", self.free_id)
        self.free_id = max(self.free_id, opnum + 1)

        setattr(self, name, opnum)
        for alias in data.get("aliases", ()):
            setattr(self, alias, opnum)

        self.name[opnum] = name
        self.arity[opnum] = int(data["arity"])

        self.process_data(opnum, name, data)

    def process_data(self, opnum, name, data):
        self.operator[opnum] = data.get("operator", None)
        self.symbol[opnum] = data.get("symbol", None)
        self.symmetric[opnum] = data.get("symmetric", False)

    def eval(self, op, args):
        if not self.operator[op]:
            raise NotImplementedError("Operator %s can not be evaluated" % self.name[op])
        return self.operator[op](*args)

    def __contains__(self, op):
        return op in self.name

    def dump(self, file=sys.stderr):
        for opnum, name in sorted(self.name.items()):
            print("%2d: %s" % (opnum, name), file=file)

class BitOP(OP):
    OPS = (
        ("XOR",  dict(operator=operator.xor,
                 symbol="^",
                 symmetric=True,
                 arity=2)),
        ("AND",  dict(operator=operator.and_,
                 symbol="&",
                 symmetric=True,
                 arity=2)),
        ("OR",   dict(operator=operator.or_,
                 symbol="|",
                 symmetric=True,
                 arity=2)),

        ("NOT",  dict(operator=lambda a: 1^a,
                 symbol="~",
                 arity=1)),

        ("ZERO", dict(operator=lambda: 0,
                  symbol="0",
                  arity=0)),
        ("ONE",  dict(operator=lambda: 1,
                  symbol="1",
                  arity=0)),

        # special nodes / ops
        ("INPUT",  dict(operator=None,
                    symbol="i",
                    arity=0)),
        ("OUTPUT", dict(operator=lambda a: a,
                    symbol="o",
                    arity=1)),
        ("FREE",   dict(operator=None,
                    symbol="f",
                    arity=1)),

        ("RANDOM", dict(operator=lambda: randint(0, 1),
                    symbol="$",
                    arity=0)),
    )

