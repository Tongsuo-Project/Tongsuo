#include <stdint.h>
 
typedef unsigned long long W;
typedef unsigned short A;
typedef unsigned char B;

void SM4_128(B *out, B *in);

enum OP {XOR, AND, OR, NOT};
