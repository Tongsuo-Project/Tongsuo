#include <stdint.h>
#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
 
typedef unsigned long long W;
typedef unsigned short A;
typedef unsigned char B;

enum OP {XOR, AND, OR, NOT};

void WBSM4_bsdummyshuffling_enc(B *in, B *out);
void WBSM4_bsdummyshuffling_dec(B *in, B *out);

