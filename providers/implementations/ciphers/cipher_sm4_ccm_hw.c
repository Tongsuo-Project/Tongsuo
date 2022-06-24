/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/* Dispatch functions for SM4 CCM mode */

/*
 * This file uses the low level SM4 functions (which are deprecated for
 * non-internal use) in order to implement provider SM4 ciphers.
 */
#include "internal/deprecated.h"

#include "cipher_sm4_ccm.h"
#include "crypto/sm4_platform.h"

static int sm4_ccm_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                           size_t keylen)
{
    PROV_SM4_CCM_CTX *actx = (PROV_SM4_CCM_CTX *)ctx;
    SM4_KEY *ks = &actx->ks.ks;

# ifdef HWSM4_CAPABLE
    if (HWSM4_CAPABLE) {
        HWSM4_set_encrypt_key(key, ks);
        CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                           (block128_f) HWSM4_encrypt);
        ctx->str = (ccm128_f)NULL;
    } else
# endif /* HWSM4_CAPABLE */
    {
        ossl_sm4_set_key(key, ks);
        CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                           (block128_f) ossl_sm4_encrypt);
        ctx->str = (ccm128_f)NULL;
    }
    ctx->key_set = 1;

    return 1;
}

static const PROV_CCM_HW sm4_ccm = {
    sm4_ccm_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};


const PROV_CCM_HW *ossl_prov_sm4_hw_ccm(size_t keybits)
{
    return &sm4_ccm;
}
