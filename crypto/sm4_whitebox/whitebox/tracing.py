#-*- coding:utf-8 -*-

import os, sys


def trace_split_batch(filename, make_output_filename=None, ntraces=64, packed=True):
    """Split batched trace into byte-packed independent traces
    Not very efficient now.
    """
    if make_output_filename is None:
        make_output_filename = lambda i: filename + ".%02d" % i
    assert 0 <= ntraces <= 64
    sz = os.stat(filename).st_size
    bytes_per_node = (ntraces + 7) // 8

    assert sz % bytes_per_node == 0, "incorrect traces size (%d traces -> %d bytes per node * ? nodes = %d bytes trace file?)" % (ntraces, bytes_per_node, sz)
    num_nodes = sz / bytes_per_node

    traces = [0 for _ in xrange(ntraces)]
    fos = [open(make_output_filename(i), "wb") for i in xrange(ntraces)]
    bits = 0
    with open(filename, "rb") as f:
        for inode in xrange(num_nodes):
            block = bytearray(f.read(bytes_per_node))
            for i in xrange(ntraces):
                bit = (block[i >> 3] >> (7 - i & 7)) & 1
                traces[i] = (traces[i] << 1) | bit

            bits += 1

            if packed:
                if inode == num_nodes - 1:
                    for i in xrange(ntraces):
                        traces[i] = traces[i] << (8 - bits)
                    bits = 8

                if bits == 8:
                    for i in xrange(ntraces):
                        fos[i].write(chr(traces[i]))
                        traces[i] = 0
                    bits = 0
            else:
                for i in xrange(ntraces):
                    fos[i].write(chr(traces[i]))
                    traces[i] = 0
                bits = 0

    for fo in fos:
        fo.close()

if __name__ == '__main__':
    trace_split_batch(sys.argv[1], ntraces=int(sys.argv[2]))
