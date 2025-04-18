#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
typedef unsigned long long W;
typedef unsigned short A;
typedef unsigned char B;

enum OP {_, XOR, AND, OR, NOT, RANDOM};

A input_addr[] = {$input_addr};
A output_addr[] = {$output_addr};
int slice = $SLICE_CNT;
B opcodes[] = $opcodes_encoded;
W ram[$ram_size];

void AES_128_encrypt(B *ct, B *pt) {
    for(int i = 0; i < 128; i++) {
        ram[input_addr[i]] = 0;
    }
    for(int j = 0; j < slice; j++){
        for(int i = 0; i < 128; i++) {
            ram[input_addr[i]] ^= ((pt[(i+j*128)/8] >> (7 - i % 8)) & 1ULL) << j;
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
        ct[i] = 0;
    }
    for(int j = 0; j < slice; j++){
        for(int i = 0; i < 128; i++) {
            ct[(i+j*128)/8] ^= ((ram[output_addr[i]]>>j)&1ULL) << (7 - i % 8);
        }
    }
}

int main() {
    B plaintext[16*64];
    B ciphertext[16*64];
    while (fread(plaintext, 1, 16*slice, stdin) == 16*slice) {
        AES_128_encrypt(ciphertext, plaintext);
        fwrite(ciphertext, 1, 16*slice, stdout);
    }
    return 0;
}