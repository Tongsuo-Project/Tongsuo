#include <stdint.h>
 
typedef unsigned long long W;
typedef unsigned short A;
typedef unsigned char B;

enum OP {XOR, AND, OR, NOT};

void SM4_128(B *out, B *in)
{
    for(int i = 0; i < 16; i++) {
        out[i] = 0;
    }
}
