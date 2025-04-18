#-*- coding:utf-8 -*-

import ctypes, os
from ctypes import *

path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "libfastcircuit.so")
lib = ctypes.cdll.LoadLibrary(path)

lib.load_circuit.restype = c_void_p

lib.circuit_compute.argtypes = (c_void_p, c_char_p, c_char_p, c_char_p, c_int)

lib.set_seed.argtypes = c_uint64,

# lib.RANDOM_ENABLED

def set_seed(seed=None):
    if seed is None: # use nanoseconds
        lib.set_seed_time()
    else:
        lib.set_seed(seed)

def randomness(on):
    if on:
        lib.RANDOM_ENABLED = 1
    else:
        lib.RANDOM_ENABLED = 0

def chunks(s, n):
    return [s[i:i+n] for i in xrange(0, len(s), n)]

class CircuitInfo(ctypes.Structure):
    _fields_ = [
        ("input_size", c_uint64),
        ("output_size", c_uint64),
        ("num_opcodes", c_uint64),
        ("opcodes_size", c_uint64),
        ("memory", c_uint64),
    ]


class FastCircuit(object):
    def __init__(self, fname):
        self.circuit = lib.load_circuit(fname)
        assert self.circuit
        self.info = CircuitInfo.from_address(self.circuit)

    def compute_one(self, input, trace_filename=None):
        output = ctypes.create_string_buffer( int((self.info.output_size + 7)//8) )
        lib.circuit_compute(self.circuit, input, output, trace_filename, 1)
        return output.raw

    def compute_batch(self, inputs, trace_filename=None):
        bytes_per_output = (self.info.output_size + 7)//8
        output = ctypes.create_string_buffer(
            int(bytes_per_output * len(inputs))
        )
        input = "".join(inputs)
        lib.circuit_compute(self.circuit, input, output, trace_filename, len(inputs))
        return chunks(output.raw, bytes_per_output)

    def compute_batches(self, inputs, trace_filename_format=None):
        outputs = []
        for i, chunk in enumerate(chunks(inputs, 64)):
            trace_filename = trace_filename_format % i if trace_filename_format else None
            outputs += self.compute_batch(chunk, trace_filename)
        return outputs


if __name__ == '__main__':
    print "input_size", FastCircuit("./circuits/test.bin").info.input_size
    print "output_size", FastCircuit("./circuits/test.bin").info.output_size
    print "num_opcodes", FastCircuit("./circuits/test.bin").info.num_opcodes
    print "opcodes_size", FastCircuit("./circuits/test.bin").info.opcodes_size
    print "memory", FastCircuit("./circuits/test.bin").info.memory
    # print FastCircuit("./circuits/test.bin").compute_one("A" * 16).encode("hex")
    # print FastCircuit("./circuits/test.bin").compute_one("A" * 16, trace_filename="./traces/test_one.bin").encode("hex")

    pts = open("plain").read()
    pts = chunks(pts, 16)
    print FastCircuit("./circuits/test.bin").compute_batch(pts, trace_filename="./traces/test_batch.bin")
