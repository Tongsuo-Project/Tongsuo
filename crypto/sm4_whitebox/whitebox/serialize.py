#-*- coding:utf-8 -*-

import sys

from whitebox.orderer import ComputationOrder, Orderer

from whitebox.tree.node.op import BitOP
OP = BitOP()


class CodeSerializer(object):
    """
    Base class for serialization (but is not necessary to use).
    Minimizes RAM usage by reusing memory cells.
    """
    reuse_memory = True
    ignore_ops = ()

    def __init__(self, **kwargs):
        for k in kwargs:
            assert hasattr(self, k), "unknown option %s" % k
        self.__dict__.update(kwargs)

    def serialize(self, circuit):
        """
        Circuit is tuple/list of bits,
        or ComputationOrder
        """
        if isinstance(circuit, ComputationOrder):
            co = circuit
        else:
            assert isinstance(circuit, (tuple, list)) and circuit[0].OP # is Bit class
            co = Orderer(circuit).compile()
        assert isinstance(co, ComputationOrder)

        self.co = co

        self.free = []
        self.bit_id = {}
        self.ram_size = 0

        self.header = []
        self.code = []

        self.serialize_start()
        co.walk_by(self)
        self.serialize_end()
        return self.header, self.code

    def serialize_start(self, co):
        pass

    def serialize_end(self, co):
        pass

    def alloc(self, bit):
        if not self.free:
            self.free.append(self.ram_size)
            self.ram_size += 1
        self.bit_id[bit] = self.free.pop()

    def action_input(self, bit):
        self.alloc(bit)
        if bit.OP.INPUT not in self.ignore_ops:
            self.serialize_input(bit)

    def action_output(self, bit):
        if bit.OP.OUTPUT not in self.ignore_ops:
            self.serialize_output(bit)

    def action_compute(self, bit):
        self.alloc(bit)
        if bit.op not in self.ignore_ops:
            self.serialize_bit(bit)

    def action_free(self, bit):
        if self.reuse_memory:
            assert bit in self.bit_id, "double free?"
            self.free.append(self.bit_id[bit])
        if bit.OP.FREE not in self.ignore_ops:
            self.serialize_free(bit)


from struct import pack, unpack
FORMATS = {1: "B", 2: "H", 4: "I", 8: "Q"} # uint8, uint16, uint32, uint64

class RawSerializer(CodeSerializer):
    """
    Basic raw serialization. Not optimal, ops can be encoded by fewer bits, etc.
    """
    # these options can be overriden by initialization
    bytes_op = 1
    bytes_input = 1
    bytes_output = 1
    bytes_addr = 2
    endian = "<"

    # preserve BitOP ordering?
    # opmap = lambda op: op
    # or explicitly map to what is implemented in the C side
    opmap = {
        OP.XOR: 1,
        OP.AND: 2,
        OP.OR: 3,
        OP.NOT: 4,
        OP.RANDOM: 5,
    }.__getitem__
    ignore_ops = OP.FREE,

    def __init__(self, **kwargs):
        super(RawSerializer, self).__init__(**kwargs)
        self.format_op = FORMATS[self.bytes_op]
        self.format_input = FORMATS[self.bytes_input]
        self.format_output = FORMATS[self.bytes_output]
        self.format_addr = FORMATS[self.bytes_addr]

    def pack(self, format, *args):
        if not args:
            return ""
        fmt = self.endian
        if len(args) > 1:
            fmt += str(len(args))
        fmt += format
        return pack(fmt, *args)

    def action_free(self, bit):
        # we process output bits manually,
        # so don't free them
        if bit in self.outputs: return
        return super(RawSerializer, self).action_free(bit)

    def serialize_start(self):
        self.outputs = set(self.co.ybits)

    def serialize_end(self):
        self.info = len(self.co.xbits), len(self.co.ybits), len(self.code), sum(map(len, self.code)), self.ram_size
        self.input_addr = [self.bit_id[xbit] for xbit in self.co.xbits]
        self.output_addr = [self.bit_id[ybit] for ybit in self.co.ybits]

        # some bug regression
        assert len(set(self.input_addr)) == len(self.co.xbits)
        assert len(set(self.output_addr)) == len(self.co.ybits)

        self.header.append(
            self.pack(FORMATS[8], *self.info)
        )
        self.header.append(
            self.pack(self.format_addr, *self.input_addr)
        )
        self.header.append(
            self.pack(self.format_addr, *self.output_addr)
        )

    def serialize_input(self, bit):
        # information is saved in the header, so no need to do anything here
        pass

    def serialize_output(self, bit):
        # information is saved in the header, so no need to do anything here
        pass

    def serialize_bit(self, bit):
        for arg in bit.args:
            assert isinstance(arg, type(bit)), "Not implemented serialization of non-Bit arguments"

        res = (
            self.pack(self.format_op, self.opmap(bit.op))
          + self.pack(self.format_addr, self.bit_id[bit])
        )
        if bit.args:
            args = [self.bit_id[bit] for bit in bit.args]
            res += self.pack(self.format_addr, *args)
        self.code.append(res)

    def serialize_to_file(self, circuit, filename):
        header, opcodes = self.serialize(circuit)
        header_data = "".join(header)
        opcodes_data = "".join(opcodes)
        with open(filename, "w") as f:
            f.write(header_data)
            f.write(opcodes_data)


class CompactRawSerializer(RawSerializer):
    """
    Compact raw serialization. opcode byte contains part of the destination address.
    """
    opmap = {
        OP.XOR: 0,
        OP.AND: 1,
        OP.OR: 2,
        OP.NOT: 3,
    }.__getitem__
    op_bits = 2
    free_bits = 6

    def serialize_bit(self, bit):
        for arg in bit.args:
            assert isinstance(arg, type(bit)), "Not implemented serialization of non-Bit arguments"

        dst = self.bit_id[bit]
        dst_hi  = dst >> 8
        if dst_hi >= (1 << self.free_bits):
            raise ValueError("Too much RAM usage for compact serializer!")
        dst_lo = dst & 0xff

        byte1 = self.opmap(bit.op) | (dst_hi << self.op_bits)
        byte2 = dst_lo

        res = (
            self.pack(self.format_op, byte1)
          + self.pack(self.format_op, byte2)
        )
        if bit.args:
            args = [self.bit_id[bit] for bit in bit.args]
            res += self.pack(self.format_addr, *args)
        self.code.append(res)
