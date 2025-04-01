#-*- coding:utf-8 -*-

import operator

class Vector(list):
    ZERO = 0
    WIDTH = None

    @classmethod
    def make(cls, lst):
        lst = list(lst)
        if cls.WIDTH is not None:
            assert len(lst) == cls.WIDTH
        return cls(lst)

    def split(self, n=2):
        assert len(self) % n == 0
        w = len(self) // n
        return Vector(self.make(self[i:i+w]) for i in xrange(0, len(self), w))

    def concat(self, *lst):
        v = list(self)
        for t in lst:
            v += list(t)
        return self.make(v)

    def rol(self, n=1):
        n %= len(self)
        return self.make(self[n:] + self[:n])

    def ror(self, n=1):
        return self.rol(-n)

    def shl(self, n=1):
        assert n >= 0
        n = min(n, len(self))
        return self.make(list(self[n:]) + [self._zero() for i in xrange(n)])

    def shr(self, n=1):
        assert n >= 0
        n = min(n, len(self))
        return self.make([self._zero() for i in xrange(n)] + list(self[:-n]))

    def _zero(self):
        """method because sometimes need different instances"""
        return self.ZERO

    def __repr__(self):
        return "<Vector len=%d list=%r>" % (len(self), list(self))

    def flatten(self):
        if isinstance(self[0], Vector):
            return self[0].concat(*self[1:])
        return reduce(operator.add, list(self))

    def permute(self, perm, inverse=False):
        """
        Perm contains indexes in original vector
        Example:
        vec  = [0, 1, 2, 3]
        perm = [1, 2, 3, 0]
        res  = [1, 2, 3, 0]
        """
        if not inverse:
            lst = [self[i] for i in perm]
        else:
            lst = [None] * len(self)
            for i, j in enumerate(perm):
                lst[j] = self[i]
        return self.make(lst)

    def map(self, f, with_coord=False):
        if with_coord:
            return self.make(f(i, v) for i, v in enumerate(self))
        else:
            return self.make(f(v) for v in self)

    def __xor__(self, other):
        assert isinstance(other, Vector)
        assert len(self) == len(other)
        return self.make(a ^ b for a, b in zip(self, other))

    def __or__(self, other):
        assert isinstance(other, Vector)
        assert len(self) == len(other)
        return self.make(a | b for a, b in zip(self, other))

    def __and__(self, other):
        assert isinstance(other, Vector)
        assert len(self) == len(other)
        return self.make(a & b for a, b in zip(self, other))

    def set(self, x, val):
        return self.make(v if i != x else val for i, v in enumerate(self))

    # for overriding
    def __add__(self, other):
        raise NotImplementedError("add vectors?")
    __radd__ = __add__
