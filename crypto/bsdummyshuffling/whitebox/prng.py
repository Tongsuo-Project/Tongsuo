#-*- coding:utf-8 -*-
# This program is based on the original work by Alex Biryukov and Aleksei Udovenko.
# Copyright (C) 2018 Alex Biryukov, Aleksei Udovenko
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
class PRNG(object):
    n = NotImplemented # state size

    def set_state(self, state):
        self.state = list(state)
        assert len(self.state) == self.n

    def step(self):
        raise NotImplementedError()


class LFSR(PRNG):
    def __init__(self, taps, state):
        self.n = len(state)
        self.set_state(state)

        self.taps = tuple(map(int, taps))
        assert all(0 <= tap < self.n for tap in taps)
        assert 0 in taps

    def step(self):
        res = reduce(lambda a, b: a ^ b, [self.state[i] for i in self.taps])
        self.state = [res] + self.state[:-1]
        return res


from random import choice
from functools import reduce

class Pool(PRNG):
    def __init__(self, prng, n=1000):
        self.prng = prng
        self.n = int(n)
        self.set_state([prng.step() for _ in range(n)])

    def step(self):
        return choice(self.state)
