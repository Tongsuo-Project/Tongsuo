#-*- coding:utf-8 -*-

from .vector import Vector


class Rect(object):
    def __init__(self, vec, h=None, w=None):
        assert h or w
        if h:
            w = len(vec) // h
        elif w:
            h = len(vec) // w
        assert w * h == len(vec)
        self.w, self.h = w, h

        self.lst = []
        for i in xrange(0, len(vec), w):
            self.lst.append(list(vec[i:i+w]))

    @classmethod
    def from_rect(cls, rect):
        self = object.__new__(cls)
        self.lst = rect
        self.h = len(rect)
        self.w = len(rect[0])
        return self

    def __getitem__(self, pos):
        y, x = pos
        return self.lst[y][x]

    def __setitem__(self, pos, val):
        y, x = pos
        self.lst[y][x] = val

    def row(self, i):
        return Vector(self.lst[i])

    def col(self, i):
        return Vector(self.lst[y][i] for y in xrange(self.h))

    def diag(self, x):
        assert self.w == self.h
        return Vector(self.lst[i][(x+i) % self.w] for i in xrange(self.h))

    def set_row(self, y, vec):
        for x in xrange(self.w):
            self.lst[y][x] = vec[x]
        return self

    def set_col(self, x, vec):
        for y in xrange(self.h):
            self.lst[y][x] = vec[y]
        return self

    def set_diag(self, x, vec):
        assert self.w == self.h
        for i in xrange(self.h):
            self.lst[i][(x+i) % self.w] = vec[i]
        return self

    def apply(self, f, with_coord=False):
        for y in xrange(self.h):
            if with_coord:
                self.lst[y] = [f(y, x, v) for x, v in enumerate(self.lst[y])]
            else:
                self.lst[y] = map(f, self.lst[y])
        return self

    def apply_row(self, x, func):
        return self.set_row(x, func(self.row(x)))

    def apply_col(self, x, func):
        return self.set_col(x, func(self.col(x)))

    def apply_diag(self, x, func):
        assert self.w == self.h
        return self.set_diag(x, func(self.diag(x)))

    def flatten(self):
        lst = []
        for v in self.lst:
            lst += v
        return Vector(lst)

    def zipwith(self, f, other):
        assert isinstance(other, Rect)
        assert self.h == other.h
        assert self.w == other.w
        return Rect(
            [f(a, b) for a, b in zip(self.flatten(), other.flatten())],
            h=self.h, w=self.w
        )

    def transpose(self):
        rect = [[self.lst[y][x] for y in xrange(self.h)] for x in xrange(self.w)]
        return Rect.from_rect(rect=rect)

    def __repr__(self):
        return "<Rect %dx%d>" % (self.h, self.w)
