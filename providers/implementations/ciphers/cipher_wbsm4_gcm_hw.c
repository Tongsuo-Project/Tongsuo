/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/* Dispatch functions for SM4 GCM mode */

/*
 * This file uses the low level wbsm4_xiao_dykey functions (which are deprecated for
 * non-internal use) in order to implement provider wbsm4_xiao_dykey ciphers.
 */
#include "internal/deprecated.h"

#include "cipher_wbsm4_gcm.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
static int wbsm4_xiao_dykey_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                           size_t keylen)
{
    PROV_WBSM4_XIAO_DYKEY_GCM_CTX *actx = (PROV_WBSM4_XIAO_DYKEY_GCM_CTX *)ctx;
    wbsm4_xiao_dykey_context *ks = &actx->ks.ks;

    ctx->ks = ks;

    wbsm4_set_key(key, ks, sizeof(wbsm4_xiao_dykey_context));
    CRYPTO_gcm128_init(&ctx->gcm, ks, (block128_f)wbsm4_xiao_dykey_encrypt);
    ctx->ctr = (ctr128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static int generic_wbsm4_xiao_dykey_gcm_cipher_update(PROV_GCM_CTX *ctx,
                                         const unsigned char *in,
                                         size_t len, unsigned char *out)
{
    if (ctx->enc) {
        if (ctx->ctr != NULL) {
            if (CRYPTO_gcm128_encrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
        } else {
            if (CRYPTO_gcm128_encrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    } else {
        if (ctx->ctr != NULL) {
            if (CRYPTO_gcm128_decrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
        } else {
            if (CRYPTO_gcm128_decrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    }
    return 1;
}

static const PROV_GCM_HW wbsm4_xiao_dykey_gcm = {
    wbsm4_xiao_dykey_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_wbsm4_xiao_dykey_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};


const PROV_GCM_HW *ossl_prov_wbsm4_xiao_dykey_hw_gcm(size_t keybits)
{
    return &wbsm4_xiao_dykey_gcm;
}
#endif
