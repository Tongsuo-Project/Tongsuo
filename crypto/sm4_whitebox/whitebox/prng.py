#-*- coding:utf-8 -*-

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

class Pool(PRNG):
    def __init__(self, prng, n=1000):
        self.prng = prng
        self.n = int(n)
        self.set_state([prng.step() for _ in xrange(n)])

    def step(self):
        return choice(self.state)
