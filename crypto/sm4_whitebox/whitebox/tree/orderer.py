#-*- coding:utf-8 -*-

from collections import Counter, defaultdict
from Queue import PriorityQueue
from random import randint, shuffle

from node import OP


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

class ComputationOrder(object):
    ACTION_COMPUTE = "compute"
    ACTION_FREE = "free"
    # ACTION_ALLOC = "alloc"

    def __init__(self, code, xbits, ybits):
        self.code = code
        self.xbits = tuple(xbits)
        self.ybits = tuple(ybits)

    def max_state(self):
        mx = 0
        counter = 0
        for action, _ in self.code:
            if action == self.ACTION_FREE:
                counter -= 1
            else:
                counter += 1
            mx = max(mx, counter)
        return mx

CO = ComputationOrder

class Orderer(object):
    def __init__(self, xbits, ybits, quiet=False):
        self.ybits = ybits
        self.xbits = list(xbits)

        self.using = {}
        self.indeg = Counter()
        self.queue = []
        self.sequential = PriorityQueue()
        self.ready = PriorityQueue()
        self.quiet = quiet

    def compile(self, max_id_rush):
        self.composite = set()

        if not self.quiet:
            print ":: CIRCUIT WALK START"
        self.visited = set()
        for b in self.ybits:
            self.dfs(b)
        del self.visited

        if not self.quiet:
            print ":: ORDERING START"
        code = tuple(self.generate(max_id_rush=max_id_rush))
        # print ":: CODE SIZE %d OPERATIONS" % len(code)
        return ComputationOrder(xbits=self.xbits, ybits=self.ybits, code=code)

    def dfs(self, b):
        if b in self.visited:
            return
        self.sequential.put((b.id, b))
        self.visited.add(b)

        if b.is_primitive():
            self.indeg[b] = 0
            self.ready.put((b.id, b))
            if b.is_const():
                # assert not b.is_const(), "not really needed assert, by better not to have consts for good orderings"
                print "WARNING", "not really needed assert, by better not to have consts for good orderings"
                for par in self.using[b]:
                    print OP.name[par.op], OP.name[b.op]
                quit(1)


            if b.is_input():
                assert b.args[0] in [bb.args[0] for bb in self.xbits], b.args[0]
                assert b in self.xbits, b.args[0]
            return

        for sub in b.args:
            if sub not in self.using:
                self.using[sub] = Multiset()
            self.using[sub].add(b)
            self.dfs(sub)

        self.indeg[b] = len(b.args)
        assert len(b.args) > 0
        self.composite.add(b)

    def generate(self, max_id_rush):
        # outputs are used and never can be freed
        for b in self.ybits:
            if b not in self.using:
                self.using[b] = Multiset()
            self.using[b].add(None)

        self.visited = set()

        while True:
            b = self.pop_queue(max_id_rush=max_id_rush)
            if b is None:
                break
            self.visited.add(b)
            assert self.indeg[b] == 0

            for sub, cnt in self.using[b].items():
                self.indeg[sub] -= cnt
                if self.indeg[sub] == 0:
                    self.ready.put((sub.id, sub))

            if b.op == OP.OUTSOURCE or b.op == OP.OUTSOURCE_CLONE:
                yield CO.ACTION_COMPUTE, b
                continue

            if b not in self.composite:
                # simple bit (input/const)
                continue

            # complex bit, compute
            # yield "alloc", b
            # alloc included in compute?

            yield CO.ACTION_COMPUTE, b

            for sub in b.args:
                # repeated bit usage?
                if b not in self.using[sub]:
                    continue
                self.using[sub].remove_all(b)
                if len(self.using[sub]) == 0:
                    if sub.is_const():
                        continue
                    # disallow reuse immutable vars
                    # if sub in self.immutable:
                        # continue
                    yield CO.ACTION_FREE, sub

    def pop_queue(self, max_id_rush):
        while self.sequential.qsize():
            _, b_first = item = self.sequential.get()
            if b_first not in self.visited:
                self.sequential.put(item)
                break
        if self.sequential.qsize() == 0:
            return

        while self.ready.qsize():
            _, b = item = self.ready.get()
            if b_first.id + max_id_rush < b.id:
                self.ready.put(item)
                break
            self.queue.append(b)

        # print self.sequential.qsize(), self.ready.qsize(), len(self.queue)
        if not self.queue:
            print "ERROR, no computable bits inside max_id_rush=%d" % max_id_rush
            print b_first.id, OP.name[b_first.op]
            print b.id, OP.name[b.op]
            quit(1)

        q = self.queue
        i = randint(0, len(q)-1)
        b = q[i]
        assert b.id <= b_first.id + max_id_rush
        q[i], q[-1] = q[-1], q[i]
        q.pop()
        return b
