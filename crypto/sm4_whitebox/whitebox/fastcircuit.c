#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "fastcircuit.h"

FILE *ftrace = NULL;

int RANDOM_ENABLED = 1;

// Randomness
void __attribute__ ((constructor)) set_seed_time() {
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    srandom(spec.tv_sec);
    srandom(random() ^ spec.tv_nsec);
}
void set_seed(uint64_t seed) {
    srandom(seed);
}
WORD randbit() {
    if (RANDOM_ENABLED)
        return random() ^ (((uint64_t)random()) << 32);
    else
        return 0;
}


Circuit *load_circuit(char *fname) {
    assert(fname);
    FILE * fd = fopen(fname, "r");
    assert(fd);

    Circuit *C = malloc(sizeof(Circuit));
    CircuitInfo *I = &C->info;

    assert(sizeof(CircuitInfo) == fread(I, 1, sizeof(CircuitInfo), fd));

    C->input_addr = malloc(sizeof(ADDR) * I->input_size);
    C->output_addr = malloc(sizeof(ADDR) * I->output_size);
    assert(C->input_addr);
    assert(C->output_addr);
    assert(I->input_size == fread(C->input_addr, sizeof(ADDR), I->input_size, fd));
    assert(I->output_size == fread(C->output_addr, sizeof(ADDR), I->output_size, fd));

    C->opcodes = malloc(sizeof(BYTE) * I->opcodes_size);
    assert(C->opcodes);
    assert(I->opcodes_size == fread(C->opcodes, sizeof(BYTE), I->opcodes_size, fd));

    C->ram = malloc(sizeof(WORD) * I->memory);
    assert(C->ram);
    fclose(fd);
    return C;
}

void free_circuit(Circuit *C) {
    free(C->input_addr);
    free(C->output_addr);
    free(C->opcodes);
    free(C->ram);
    free(C);
}

/*
Bits in bytes: MSB to LSB
Bytes in word: LSB to MSB, because will be packed as Little Endian
*/
WORD io_bit(int bit) {
    int lo = bit & 7;
    bit -= lo;
    bit += 7 - lo;
    return bit;
}
void circuit_compute(Circuit *C, uint8_t *inp, uint8_t *out, char *trace_filename, int batch) {
    CircuitInfo *I = &C->info;
    WORD *ram = C->ram;
    bzero(ram, I->memory);

    WORD NOTMASK = 0;
    for (int j = 0; j < batch; j++)
        NOTMASK |= 1 << io_bit(j);

    FILE * ftrace = NULL;
    if (trace_filename) {
        ftrace = fopen(trace_filename, "w");
        assert(ftrace);
    }
    int trace_item_bytes = 1;
    if (batch > 8) trace_item_bytes = 2;
    if (batch > 16) trace_item_bytes = 4;
    if (batch > 32) trace_item_bytes = 8;

    assert(1 <= batch && batch <= 64);
    int bytes_per_input = (I->input_size + 7) / 8;
    int bytes_per_output = (I->output_size + 7) / 8;

    // load input
    for (int j = 0; j < batch; j++) {
        for (int i = 0; i < I->input_size; i++) {
            int byte = i >> 3;
            int bit = 7 - (i & 7);
            WORD value = (inp[byte]>>bit) & 1;

            if (j == 0) ram[C->input_addr[i]] = 0;
            ram[C->input_addr[i]] |= value << io_bit(j);
        }
        inp += bytes_per_input;
    }

    // compute circuit
    BYTE *p = C->opcodes;
    for(int i = 0; i < I->num_opcodes; i++) {
        BYTE op = *p++;
        ADDR dst = *((ADDR *)p); p+=2;
        ADDR a, b;
        switch (op) {
        case XOR:
            a = *((ADDR *)p); p+=2;
            b = *((ADDR *)p); p+=2;
            ram[dst] = ram[a] ^ ram[b];
            break;
        case AND:
            a = *((ADDR *)p); p+=2;
            b = *((ADDR *)p); p+=2;
            ram[dst] = ram[a] & ram[b];
            break;
        case OR:
            a = *((ADDR *)p); p+=2;
            b = *((ADDR *)p); p+=2;
            ram[dst] = ram[a] | ram[b];
            break;
        case NOT:
            a = *((ADDR *)p); p+=2;
            ram[dst] = NOTMASK ^ ram[a];
            break;
        case RANDOM:
            ram[dst] = randbit();
            break;
        default:
            printf("unknown opcode %d\n", op);
            exit(0);
        }

        if (ftrace) {
            fwrite(ram+dst, 1, trace_item_bytes, ftrace);
        }
    }

    // extract output
    for (int j = 0; j < batch; j++) {
        for (int i = 0; i < I->output_size; i++) {
            int byte = i >> 3;
            int bit = 7 - (i & 7);
            WORD value = (ram[C->output_addr[i]] >> io_bit(j)) & 1;

            if (bit == 7) out[byte] = 0;
            out[byte] |= value << bit;
        }
        out += bytes_per_output;
    }
    if (ftrace) fclose(ftrace);
}
