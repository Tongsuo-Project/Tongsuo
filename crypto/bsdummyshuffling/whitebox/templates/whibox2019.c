#include "crypto/bsdummyshuffling.h"

static int slice = $SLICE_CNT;
static W ram[$ram_size];

static A input_addr_enc[] = {$input_addr_enc};
static A output_addr_enc[] = {$output_addr_enc};
static B opcodes_enc[] = $opcodes_encoded_enc;

static A input_addr_dec[] = {$input_addr_dec};
static A output_addr_dec[] = {$output_addr_dec};
static B opcodes_dec[] = $opcodes_decoded_dec;

void WBSM4_bsdummyshuffling_enc(B *in, B *out) {
    int i;
    int j;
    #define pop() p+=sizeof(A)
    B *p = opcodes_enc;
    A a, b;
    B op;
    A dst;

    for(i = 0; i < 128; i++) {
        ram[input_addr_enc[i]] = 0;
    }
    for(j = 0; j < slice; j++){
        for(i = 0; i < 128; i++) {
            ram[input_addr_enc[i]] ^= ((in[(i+j*128)/8] >> (7 - i % 8)) & 1ULL) << j;
        }
    }

    for(i = 0; i < $num_opcodes; i++) {
        op = *p++;
        dst = *((A *)p); pop();
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
            ram[dst] = 0;
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
            out[(i+j*128)/8] ^= ((ram[output_addr_enc[i]]>>j)&1ULL) << (7 - i % 8);
        }
    }
}

void WBSM4_bsdummyshuffling_dec(B *in, B *out) {
    int i;
    int j;
    #define pop() p+=sizeof(A)
    B *p = opcodes_dec;
    A a, b;
    B op;
    A dst;

    for(i = 0; i < 128; i++) {
        ram[input_addr_dec[i]] = 0;
    }
    for(j = 0; j < slice; j++){
        for(i = 0; i < 128; i++) {
            ram[input_addr_dec[i]] ^= ((in[(i+j*128)/8] >> (7 - i % 8)) & 1ULL) << j;
        }
    }

    for(i = 0; i < $num_opcodes; i++) {
        op = *p++;
        dst = *((A *)p); pop();
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
            ram[dst] = 0;
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
            out[(i+j*128)/8] ^= ((ram[output_addr_dec[i]]>>j)&1ULL) << (7 - i % 8);
        }
    }
}