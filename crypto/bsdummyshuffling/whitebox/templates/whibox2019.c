#include "crypto/bsdummyshuffling.h"


A input_addr[] = {$input_addr};
A output_addr[] = {$output_addr};
int slice = $SLICE_CNT;
B opcodes[] = $opcodes_encoded;
W ram[$ram_size];

void SM4_128(B *out, B *in) {
    for(int i = 0; i < 128; i++) {
        ram[input_addr[i]] = 0;
    }
    for(int j = 0; j < slice; j++){
        for(int i = 0; i < 128; i++) {
            ram[input_addr[i]] ^= ((in[(i+j*128)/8] >> (7 - i % 8)) & 1ULL) << j;
        }
    }

    #define pop() p+=sizeof(A)
    B *p = opcodes;
    for(int i = 0; i < $num_opcodes; i++) {
        B op = *p++;
        A dst = *((A *)p); pop();
        A a, b;
        switch (op) {
        case XOR:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram[dst] = ram[a] ^ ram[b];
            break;
        case AND:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram[dst] = ram[a] & ram[b];
            break;
        case OR:
            a = *((A *)p); pop();
            b = *((A *)p); pop();
            ram[dst] = ram[a] | ram[b];
            break;
        case NOT:
            a = *((A *)p); pop();
            ram[dst] = ((W)-1) ^ ram[a];
            break;
        case RANDOM:
            ram[dst] = 0; // not useful for contest (or implement your rand and obfuscate...)
            break;
        default:
            return; // ouch?
        }
    }

    for(int i = 0; i < 16*slice; i++) {
        out[i] = 0;
    }
    for(int j = 0; j < slice; j++){
        for(int i = 0; i < 128; i++) {
            out[(i+j*128)/8] ^= ((ram[output_addr[i]]>>j)&1ULL) << (7 - i % 8);
        }
    }
}