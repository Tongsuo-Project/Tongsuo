/*
 * Copyright 2023-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef SM4TH_KEY_H
# define SM4TH_KEY_H

# include "crypto/sm4th.h"
# include "params.h"

# include <openssl/evp.h>
# include <stdint.h>

/*
 * SM4th keys:
 *   pk = OWF input (p) || OWF output (c), c = SM4_k(p)
 *   sk = OWF input (p) || OWF key (k)
 */
struct sm4th_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const params_t *params;
    int variant;
    unsigned int has_k;

    /* Prefetched SHAKE-128 (same pattern as ML_DSA_KEY). */
    EVP_MD *shake128_md;

    uint8_t k[SM4TH_128_BYTES];
    uint8_t p[SM4TH_128_BYTES];
    uint8_t c[SM4TH_128_BYTES];
};

#endif
