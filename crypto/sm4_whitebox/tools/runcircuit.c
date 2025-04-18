#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

#include "fastcircuit.h"

// void AES_128_encrypt(char *ct, char *pt) {
//     compute(pt, ct, 1);
// }

int main(int argc, char *argv[]) {
    if (getenv("RANDOM_SEED"))
        set_seed(atoi(getenv("RANDOM_SEED")));

    char *trace_fname = getenv("TRACE");

    if (argc <= 1) {
        printf("Usage: %s <circuit_file>\n", argv[0]);
        return -1;
    }
    // read circuit
    char *fname = argv[1];
    assert(fname);
    Circuit *C = load_circuit(fname);

    char plaintexts[64][16];
    char ciphertexts[64][16];
    int nread = 0;
    int eof = 0;
    while (1) {
        if (fread(plaintexts + nread, 1, 16, stdin) != 16)
            eof = 1;
        else
            nread++;

        if (nread == 64 || (eof && nread)) {
            fprintf(stderr, "computing batch %d\n", nread);
            circuit_compute(C, (unsigned char*)plaintexts, (unsigned char*)ciphertexts, trace_fname, nread);
            fwrite(ciphertexts, nread, 16, stdout);
            nread = 0;
        }
        if (eof) break;
    }
    return 0;
}
