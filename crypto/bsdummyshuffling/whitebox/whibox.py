#-*- coding:utf-8 -*-

"""
Helper module for generating submission code right from the circuit.
"""

import sys,os

from whitebox.serialize import RawSerializer, CompactRawSerializer
from whitebox.templates import Template, encode_bytes

def whibox_generate(if_enc, slice_cnt, ct, filename):
    if if_enc==0:
        try:
            RS = CompactRawSerializer()
            header, opcodes = RS.serialize(ct)
            template = "whibox2019compact.c"
            kw = dict(op_bits=RS.op_bits)
            print("Compact serialization succeeded!", file=sys.stderr)
        except ValueError:
            print("Compact serialize failed (too much ram usage), falling back to basic one.", file=sys.stderr)
            RS = RawSerializer()
            header, opcodes = RS.serialize(ct)
            template = "whibox2019.c"
            kw = dict()

        opcodes_data = b''.join(opcodes)

        code = Template(template).subs(
            input_addr_dec=RS.input_addr,
            output_addr_dec=RS.output_addr,
            SLICE_CNT=slice_cnt,
            opcodes_decoded_dec='{%s}' %  encode_bytes(opcodes_data),
            ram_size=RS.ram_size,
            num_opcodes=len(opcodes),
            **kw
        )
    else:
        RS = RawSerializer()
        header, opcodes = RS.serialize(ct)
        template = os.path.join("..", "..", "bsdummyshuffling.c")
        opcodes_data = b''.join(opcodes)
        code = Template(template).subs(
            input_addr_enc=RS.input_addr,
            output_addr_enc=RS.output_addr,
            opcodes_encoded_enc='{%s}' %  encode_bytes(opcodes_data),
        )

    with open(filename, "w") as f:
        f.write(code)
    
    print("Source code %.2f MB, opcodes: %.2f MB" % (len(code) / 2.0**20, len(opcodes_data) / 2.0**20))
    print("RAM: %d bits (bytes)" % RS.ram_size)
    print("write in %s" %filename)
    return RS, code
