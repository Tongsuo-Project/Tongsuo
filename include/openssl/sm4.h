/*
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SM4_H
# define HEADER_SM4_H

# if !defined(OPENSSL_NO_SM4) && !defined(OPENSSL_NO_EXPORT_SM4)
#  include <openssl/e_os2.h>
#  include <stddef.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

# define SM4_ENCRYPT     1
# define SM4_DECRYPT     0

# define SM4_BLOCK_SIZE    16
# define SM4_KEY_SCHEDULE  32

typedef struct SM4_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

int SM4_set_key(const uint8_t *key, SM4_KEY *ks);

void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
