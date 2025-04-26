#-*- coding:utf-8 -*-

class Multiset(object):
    def __init__(self):
        self.data = {}

    def add(self, obj, num=1):
        self.data.setdefault(obj, 0)
        self.data[obj] += num

    def remove(self, obj, num=1):
        self.data[obj] -= num
        assert self.data[obj] >= 0
        if self.data[obj] == 0:
            del self.data[obj]

    def remove_all(self, obj):
        del self.data[obj]

    def items(self):
        return self.data.items()

    def __len__(self):
        return len(self.data)

    def __contains__(self, obj):
        return obj in self.data

    def __iter__(self):
        return self.data.__iter__()

    def __nonzero__(self):
        return bool(self.data)

class ComputationOrder(object):
    ACTION_COMPUTE = "compute"
    ACTION_INPUT = "input"
    ACTION_FREE = "free"
    ACTION_OUTPUT = "output"

    def __init__(self, code, xbits, ybits):
        self.code = code
        self.xbits = tuple(xbits)
        self.ybits = tuple(ybits)

    def walk_by(self, visitor):
        methods = {}
        for k, v in type(self).__dict__.items():
            if k.startswith("ACTION_"):
                method = getattr(visitor, "action_" + v, None)
                if method:
                    methods[v] = method

        for action, bit in self.code:
            if action in methods:
                methods[action](bit)

CO = ComputationOrder

class Orderer(object):
    """
    Orders circuit computations in a sequence.
    This class does it simply by Bit.id, can be done differently, e.g. with some randomization
    """
    def __init__(self, ybits, quiet=False):
        self.xbits = list(circuit_inputs(ybits))
        self.ybits = ybits

        self.quiet = quiet

    def log(self, *args):
        if not self.quiet:
            print "::",
            for arg in args:
                print arg,
            print

    def compile(self):
        self.log("circuit walk")

        visited = set()
        using = {}

        q = []
        for b in self.ybits:
            q.append(b)
            visited.add(b)

            # output bits are used always
            using[b] = Multiset()
            using[b].add(None)

        while q:
            b = q.pop()
            for sub in b.args:
                if type(sub) == type(b):
                    if sub not in visited:
                        visited.add(sub)
                        q.append(sub)

                    if sub not in using:
                        using[sub] = Multiset()
                    using[sub].add(b)

        self.log("ordering", len(visited), "nodes")

        order = sorted(visited, key=lambda b: b.id)
        ready = set()
        freed = set()
        code = []
        for b in order:
            if b.is_input():
                code.append((CO.ACTION_INPUT, b))
                ready.add(b)
                continue
            if b.is_const():
                ready.add(b)
                continue

            code.append((CO.ACTION_COMPUTE, b))
            ready.add(b)

            for sub in b.args:
                if type(sub) != type(b):
                    continue
                assert sub in ready
                assert sub not in freed
                assert b in using[sub]
                using[sub].remove(b)
                # using[sub].remove_all(b)
                # do not free output bits immediately
                if not using[sub]:
                    code.append((CO.ACTION_FREE, sub))
                    freed.add(sub)

        for b in self.ybits:
            code.append((CO.ACTION_OUTPUT, b))
            code.append((CO.ACTION_FREE, b))

        code = tuple(code)

        self.log("code size: %d operations" % len(code))

        return ComputationOrder(xbits=self.xbits, ybits=self.ybits, code=code)

def circuit_filter(ybits, filter=None):
    visited = set()
    q = []
    for b in ybits:
        q.append(b)
        visited.add(b)
    while q:
        b = q.pop()
        if filter(b):
            yield b
        for sub in b.args:
            if type(sub) == type(b) and sub not in visited:
                visited.add(sub)
                q.append(sub)

def circuit_filter_op(ybits, op):
    return circuit_filter(ybits, lambda b: b.op == op)

def circuit_inputs(ybits):
    res = list(circuit_filter(ybits, filter=lambda b: b.is_input()))
    res.sort(key=lambda b: b.id)
    return tuple(res)
