#-*- coding:utf-8 -*-
# This program is based on the original work by Alex Biryukov and Aleksei Udovenko.
# Copyright (C) 2018 Alex Biryukov, Aleksei Udovenko
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
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
            print("Compact serialization succeeded!")
        except ValueError:
            print("Compact serialize failed (too much ram usage), falling back to basic one.")
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
            ram_size_dec=RS.ram_size,
            num_opcodes_dec=len(opcodes),
            **kw
        )
    else:
        try:
            RS = CompactRawSerializer()
            header, opcodes = RS.serialize(ct)
            kw = dict(op_bits=RS.op_bits)
            print("Compact serialization succeeded!")
        except ValueError:
            print("Compact serialize failed (too much ram usage), falling back to basic one.")
            RS = RawSerializer()
            header, opcodes = RS.serialize(ct)
            kw = dict()
        
        template = os.path.join("..", "..", "bsdummyshuffling.c")
        opcodes_data = b''.join(opcodes)
        code = Template(template).subs(
            input_addr_enc=RS.input_addr,
            output_addr_enc=RS.output_addr,
            opcodes_encoded_enc='{%s}' %  encode_bytes(opcodes_data),
            ram_size_enc=RS.ram_size,
            num_opcodes_enc=len(opcodes),
        )

    with open(filename, "w") as f:
        f.write(code)
    
    print("Source code %.2f MB, opcodes: %.2f MB" % (len(code) / 2.0**20, len(opcodes_data) / 2.0**20))
    print("RAM: %d bits (bytes)" % RS.ram_size)
    print("write in %s" %filename)
    return RS, code
