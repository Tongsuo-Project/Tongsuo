/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "include/crypto/zuc.h"
#include "prov/ciphercommon.h"

typedef struct {
    PROV_CIPHER_CTX base;     /* must be first */
    union {
        OSSL_UNION_ALIGN;
        ZUC_KEY ks;
    } ks;
} PROV_ZUC_EEA3_CTX;

typedef struct prov_cipher_hw_zuc_eea3_st {
    PROV_CIPHER_HW base; /* must be first */
    int (*initiv)(PROV_CIPHER_CTX *ctx);
    void (*cleanup)(PROV_ZUC_EEA3_CTX *ctx);
} PROV_CIPHER_HW_ZUC_EEA3;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_zuc_128_eea3(size_t keybits);

OSSL_FUNC_cipher_encrypt_init_fn ossl_zuc_128_eea3_einit;
OSSL_FUNC_cipher_decrypt_init_fn ossl_zuc_128_eea3_dinit;
void ossl_zuc_128_eea3_initctx(PROV_ZUC_EEA3_CTX *ctx);
