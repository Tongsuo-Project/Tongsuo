#-*- coding:utf-8 -*-

"""
Helper module for generating submission code right from the circuit.
"""

import sys

from whitebox.serialize import RawSerializer, CompactRawSerializer
from whitebox.templates import Template, encode_bytes

def whibox_generate(slice_cnt, ct, filename, comment=""):
    try:
        RS = CompactRawSerializer()
        header, opcodes = RS.serialize(ct)
        template = "whibox2019compact.c"
        kw = dict(op_bits=RS.op_bits)
        print >>sys.stderr, "Compact serialization succeeded!"
    except ValueError:
        print >>sys.stderr, "Compact serialize failed (too much ram usage), falling back to basic one."
        RS = RawSerializer()
        header, opcodes = RS.serialize(ct)
        template = "whibox2019.c"
        kw = dict()

    opcodes_data = "".join(opcodes)

    code = Template(template).subs(
        input_addr=RS.input_addr,
        output_addr=RS.output_addr,
        SLICE_CNT=slice_cnt,
        opcodes_encoded='"%s"' %  encode_bytes(opcodes_data),
        ram_size=RS.ram_size,
        num_opcodes=len(opcodes),
        comment=comment,
        **kw
    )
    with open(filename, "w") as f:
        f.write(code)
    print >>sys.stderr, "Source code %.2f MB, opcodes: %.2f MB" % (len(code) / 2.0**20, len(opcodes_data) / 2.0**20)
    print >>sys.stderr, "RAM: %d bits (bytes)" % RS.ram_size
    return RS, code
