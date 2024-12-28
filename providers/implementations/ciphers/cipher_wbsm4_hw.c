/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "cipher_wbsm4.h"

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
static int cipher_hw_wbsm4_xiaolai_initkey(PROV_CIPHER_CTX *ctx,
                                           const unsigned char *key,
                                           size_t keylen)
{
    PROV_WBSM4_XIAOLAI_CTX *sctx = (PROV_WBSM4_XIAOLAI_CTX *)ctx;
    wbsm4_xiaolai_key *ks = &sctx->ks.ks;

    ctx->ks = ks;
    if (ctx->enc || (ctx->mode != EVP_CIPH_ECB_MODE &&
        ctx->mode != EVP_CIPH_CBC_MODE)) {
        wbsm4_xiaolai_set_key(key, ks);
        ctx->block = (block128_f)wbsm4_xiaolai_encrypt;
    } else {
        ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);
        return 0;
    }

    return 1;
}

IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_wbsm4_xiaolai_copyctx,
                            PROV_WBSM4_XIAOLAI_CTX)

#define PROV_CIPHER_HW_wbsm4_xiaolai_mode(mode)              \
    static const PROV_CIPHER_HW wbsm4_xiaolai_##mode = {     \
        cipher_hw_wbsm4_xiaolai_initkey,                     \
        ossl_cipher_hw_generic_##mode,                       \
        cipher_hw_wbsm4_xiaolai_copyctx                      \
    };                                                       \
    const PROV_CIPHER_HW *                                   \
    ossl_prov_cipher_hw_wbsm4_xiaolai_##mode(size_t keybits) \
    {                                                        \
        return &wbsm4_xiaolai_##mode;                        \
    }

PROV_CIPHER_HW_wbsm4_xiaolai_mode(cbc);
PROV_CIPHER_HW_wbsm4_xiaolai_mode(ecb);
PROV_CIPHER_HW_wbsm4_xiaolai_mode(ofb128);
PROV_CIPHER_HW_wbsm4_xiaolai_mode(cfb128);
PROV_CIPHER_HW_wbsm4_xiaolai_mode(ctr);
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
static int cipher_hw_wbsm4_baiwu_initkey(PROV_CIPHER_CTX *ctx,
                                         const unsigned char *key,
                                         size_t keylen)
{
    PROV_WBSM4_BAIWU_CTX *sctx = (PROV_WBSM4_BAIWU_CTX *)ctx;
    wbsm4_baiwu_key *ks = &sctx->ks.ks;

    ctx->ks = ks;
    if (ctx->enc || (ctx->mode != EVP_CIPH_ECB_MODE &&
        ctx->mode != EVP_CIPH_CBC_MODE)) {
        wbsm4_baiwu_set_key(key, ks);
        ctx->block = (block128_f)wbsm4_baiwu_encrypt;
    } else {
        ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);
        return 0;
    }

    return 1;
}

IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_wbsm4_baiwu_copyctx,
                            PROV_WBSM4_BAIWU_CTX)

#define PROV_CIPHER_HW_wbsm4_baiwu_mode(mode)              \
    static const PROV_CIPHER_HW wbsm4_baiwu_##mode = {     \
        cipher_hw_wbsm4_baiwu_initkey,                     \
        ossl_cipher_hw_generic_##mode,                     \
        cipher_hw_wbsm4_baiwu_copyctx                      \
    };                                                     \
    const PROV_CIPHER_HW *                                 \
    ossl_prov_cipher_hw_wbsm4_baiwu_##mode(size_t keybits) \
    {                                                      \
        return &wbsm4_baiwu_##mode;                        \
    }

PROV_CIPHER_HW_wbsm4_baiwu_mode(cbc);
PROV_CIPHER_HW_wbsm4_baiwu_mode(ecb);
PROV_CIPHER_HW_wbsm4_baiwu_mode(ofb128);
PROV_CIPHER_HW_wbsm4_baiwu_mode(cfb128);
PROV_CIPHER_HW_wbsm4_baiwu_mode(ctr);
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
static int cipher_hw_wbsm4_wsise_initkey(PROV_CIPHER_CTX *ctx,
                                         const unsigned char *key,
                                         size_t keylen)
{
    PROV_WBSM4_WSISE_CTX *sctx = (PROV_WBSM4_WSISE_CTX *)ctx;
    wbsm4_wsise_key *ks = &sctx->ks.ks;

    ctx->ks = ks;
    if (ctx->enc || (ctx->mode != EVP_CIPH_ECB_MODE &&
        ctx->mode != EVP_CIPH_CBC_MODE))
    {
        wbsm4_wsise_set_key(key, ks);
        ctx->block = (block128_f)wbsm4_wsise_encrypt;
    }
    else
    {
        ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);
        return 0;
    }

    return 1;
}

IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_wbsm4_wsise_copyctx,
                            PROV_WBSM4_WSISE_CTX)

#define PROV_CIPHER_HW_wbsm4_wsise_mode(mode)              \
    static const PROV_CIPHER_HW wbsm4_wsise_##mode = {     \
        cipher_hw_wbsm4_wsise_initkey,                     \
        ossl_cipher_hw_generic_##mode,                     \
        cipher_hw_wbsm4_wsise_copyctx                      \
    };                                                     \
    const PROV_CIPHER_HW *                                 \
    ossl_prov_cipher_hw_wbsm4_wsise_##mode(size_t keybits) \
    {                                                      \
        return &wbsm4_wsise_##mode;                        \
    }

PROV_CIPHER_HW_wbsm4_wsise_mode(cbc);
PROV_CIPHER_HW_wbsm4_wsise_mode(ecb);
PROV_CIPHER_HW_wbsm4_wsise_mode(ofb128);
PROV_CIPHER_HW_wbsm4_wsise_mode(cfb128);
PROV_CIPHER_HW_wbsm4_wsise_mode(ctr);
#endif /* OPENSSL_NO_WBSM4_WSISE */
