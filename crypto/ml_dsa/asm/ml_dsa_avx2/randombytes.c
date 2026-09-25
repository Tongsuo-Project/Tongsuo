#include "ml_dsa_avx2_target.h"
#include <openssl/rand.h>
#include "randombytes.h"

void randombytes(uint8_t *out, size_t outlen)
{
    RAND_bytes(out, (int)outlen);
}
