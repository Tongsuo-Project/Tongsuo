#-*- coding:utf-8 -*-

import sys, os
from whitebox.fastcircuit import FastCircuit, chunks
from whitebox.tracing import trace_split_batch

FC = FastCircuit(sys.argv[1])
NAME = os.path.basename(sys.argv[1])
N = int(sys.argv[2])

pts = [os.urandom(16) for _ in xrange(N)]

cts = FC.compute_batches(
    inputs=pts,
    trace_filename_format="./traces/" + NAME + ".%d"
)
for i in xrange((N+63)//64):
    print "splitting", i
    filename = "./traces/" + NAME + ".%d" % i
    trace_split_batch(
        filename=filename,
        make_output_filename=lambda j: "./traces/%04d.bin" % (i * 64 + j),
        ntraces=64,
        packed=True)
    os.unlink(filename)

for i, (pt, ct) in enumerate(zip(pts, cts)):
    with open("traces/%04d.pt" % i, "wb") as f:
        f.write(pt)
    with open("traces/%04d.ct" % i, "wb") as f:
        f.write(ct)

