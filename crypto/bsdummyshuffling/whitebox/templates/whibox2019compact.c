/* This program is based on the original work by Alex Biryukov and Aleksei Udovenko.
 * Copyright (C) 2018 Alex Biryukov, Aleksei Udovenko
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 * You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
 */
#include "crypto/bsdummyshuffling.h"

static int slice = $SLICE_CNT;

static A input_addr_enc[] = {$input_addr_enc};
static A output_addr_enc[] = {$output_addr_enc};
static B opcodes_enc[] = $opcodes_encoded_enc;
static W ram_enc[$ram_size_enc];

static A input_addr_dec[] = {$input_addr_dec};
static A output_addr_dec[] = {$output_addr_dec};
static B opcodes_dec[] = $opcodes_decoded_dec;
static W ram_dec[$ram_size_dec];


void WBSM4_bsdummyshuffling_enc(B *in, B *out) {
    int i;
    int j;
    #define pop() p+=sizeof(A)
    B *p = opcodes_enc;
    B op_mask = (1 << $op_bits) - 1;
    B op;
    A dst;
    A a, b;

    for(i = 0; i < 128; i++) {
        ram_enc[input_addr_enc[i]] = 0;
    }
    for(j = 0; j < slice; j++){
        for(i = 0; i < 128; i++) {
            ram_enc[input_addr_enc[i]] ^= ((in[(i+j*128)/8] >> (7 - i % 8)) & 1ULL) << j;
        }
    }

    for(i = 0; i < $num_opcodes_enc; i++) {
        op = *p++;
        dst = *p++;


        dst |= (op >> $op_bits) << 8;
        op &= op_mask;

        switch (op) {
        case XOR:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram_enc[dst] = ram_enc[a] ^ ram_enc[b];
            break;
        case AND:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram_enc[dst] = ram_enc[a] & ram_enc[b];
            break;
        case OR:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram_enc[dst] = ram_enc[a] | ram_enc[b];
            break;
        case NOT:
            a = *((A *)p); pop();
            ram_enc[dst] = ((W)-1) ^ ram_enc[a];
            break;
        default:
            return;
        }
    }


    for(i = 0; i < 16*slice; i++) {
        out[i] = 0;
    }
    for(j = 0; j < slice; j++){
        for(i = 0; i < 128; i++) {
            out[(i+j*128)/8] ^= ((ram_enc[output_addr_enc[i]]>>j)&1ULL) << (7 - i % 8);
        }
    }
}

void WBSM4_bsdummyshuffling_dec(B *in, B *out) {
    int i;
    int j;
    #define pop() p+=sizeof(A)
    B *p = opcodes_dec;
    B op_mask = (1 << $op_bits) - 1;
    B op;
    A dst;
    A a, b;

    for(i = 0; i < 128; i++) {
        ram_dec[input_addr_dec[i]] = 0;
    }
    for(j = 0; j < slice; j++){
        for(i = 0; i < 128; i++) {
            ram_dec[input_addr_dec[i]] ^= ((in[(i+j*128)/8] >> (7 - i % 8)) & 1ULL) << j;
        }
    }

    for(i = 0; i < $num_opcodes_dec; i++) {
        op = *p++;
        dst = *p++;


        dst |= (op >> $op_bits) << 8;
        op &= op_mask;

        switch (op) {
        case XOR:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram_dec[dst] = ram_dec[a] ^ ram_dec[b];
            break;
        case AND:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram_dec[dst] = ram_dec[a] & ram_dec[b];
            break;
        case OR:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram_dec[dst] = ram_dec[a] | ram_dec[b];
            break;
        case NOT:
            a = *((A *)p); pop();
            ram_dec[dst] = ((W)-1) ^ ram_dec[a];
            break;
        default:
            return;
        }
    }


    for(i = 0; i < 16*slice; i++) {
        out[i] = 0;
    }
    for(j = 0; j < slice; j++){
        for(i = 0; i < 128; i++) {
            out[(i+j*128)/8] ^= ((ram_dec[output_addr_dec[i]]>>j)&1ULL) << (7 - i % 8);
        }
    }
}
