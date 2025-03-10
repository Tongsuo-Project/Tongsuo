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

// xiao_stkey
#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
static int cipher_hw_wbsm4_xiao_stkey_initkey(PROV_CIPHER_CTX *ctx,
                                            const unsigned char *key, size_t keylen)
{
    PROV_WBSM4_XIAO_STKEY_CTX *sctx = (PROV_WBSM4_XIAO_STKEY_CTX *)ctx;
    wbsm4_xiao_stkey_context *ks = &sctx->ks.ks;

    ctx->ks = ks;
    if (ctx->enc || (ctx->mode != EVP_CIPH_ECB_MODE && ctx->mode != EVP_CIPH_CBC_MODE))
    {
        wbsm4_set_key(key, ks, sizeof(wbsm4_xiao_stkey_context));
        ctx->block = (block128_f)wbsm4_xiao_stkey_encrypt;
    }
    else
    {
        wbsm4_set_key(key, ks, sizeof(wbsm4_xiao_stkey_context));
        ctx->block = (block128_f)wbsm4_xiao_stkey_decrypt;
    }

    return 1;
}

IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_wbsm4_xiao_stkey_copyctx, PROV_WBSM4_XIAO_STKEY_CTX)

#define PROV_CIPHER_HW_wbsm4_xiao_stkey_mode(mode)                                    \
    static const PROV_CIPHER_HW wbsm4_xiao_stkey_##mode = {                           \
        cipher_hw_wbsm4_xiao_stkey_initkey,                                           \
        ossl_cipher_hw_generic_##mode,                                             \
        cipher_hw_wbsm4_xiao_stkey_copyctx};                                          \
    const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_xiao_stkey_##mode(size_t keybits) \
    {                                                                              \
        return &wbsm4_xiao_stkey_##mode;                                              \
    }

PROV_CIPHER_HW_wbsm4_xiao_stkey_mode(cbc);
PROV_CIPHER_HW_wbsm4_xiao_stkey_mode(ecb);
PROV_CIPHER_HW_wbsm4_xiao_stkey_mode(ofb128);
PROV_CIPHER_HW_wbsm4_xiao_stkey_mode(cfb128);
PROV_CIPHER_HW_wbsm4_xiao_stkey_mode(ctr);
#endif

#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
static int cipher_hw_wbsm4_jin_stkey_initkey(PROV_CIPHER_CTX *ctx,
                                            const unsigned char *key, size_t keylen)
{
    PROV_WBSM4_JIN_STKEY_CTX *sctx = (PROV_WBSM4_JIN_STKEY_CTX *)ctx;
    wbsm4_jin_stkey_context *ks = &sctx->ks.ks;

    ctx->ks = ks;
    if (ctx->enc || (ctx->mode != EVP_CIPH_ECB_MODE && ctx->mode != EVP_CIPH_CBC_MODE))
    {
        wbsm4_set_key(key, ks, sizeof(wbsm4_jin_stkey_context));
        ctx->block = (block128_f)wbsm4_jin_stkey_encrypt;
    }
    else
    {
        wbsm4_set_key(key, ks, sizeof(wbsm4_jin_stkey_context));
        ctx->block = (block128_f)wbsm4_jin_stkey_decrypt;
    }

    return 1;
}

IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_wbsm4_jin_stkey_copyctx, PROV_WBSM4_JIN_STKEY_CTX)

#define PROV_CIPHER_HW_wbsm4_jin_stkey_mode(mode)                                    \
    static const PROV_CIPHER_HW wbsm4_jin_stkey_##mode = {                           \
        cipher_hw_wbsm4_jin_stkey_initkey,                                           \
        ossl_cipher_hw_generic_##mode,                                             \
        cipher_hw_wbsm4_jin_stkey_copyctx};                                          \
    const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_jin_stkey_##mode(size_t keybits) \
    {                                                                              \
        return &wbsm4_jin_stkey_##mode;                                              \
    }

PROV_CIPHER_HW_wbsm4_jin_stkey_mode(cbc);
PROV_CIPHER_HW_wbsm4_jin_stkey_mode(ecb);
PROV_CIPHER_HW_wbsm4_jin_stkey_mode(ofb128);
PROV_CIPHER_HW_wbsm4_jin_stkey_mode(cfb128);
PROV_CIPHER_HW_wbsm4_jin_stkey_mode(ctr);
#endif

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
static int cipher_hw_wbsm4_xiao_dykey_initkey(PROV_CIPHER_CTX *ctx,
                                            const unsigned char *key, size_t keylen)
{
    PROV_WBSM4_XIAO_DYKEY_CTX *sctx = (PROV_WBSM4_XIAO_DYKEY_CTX *)ctx;
    wbsm4_xiao_dykey_context *ks = &sctx->ks.ks;

    ctx->ks = ks;
    if (ctx->enc || (ctx->mode != EVP_CIPH_ECB_MODE && ctx->mode != EVP_CIPH_CBC_MODE))
    {
        wbsm4_set_key(key, ks, sizeof(wbsm4_xiao_dykey_context));
        ctx->block = (block128_f)wbsm4_xiao_dykey_encrypt;
    }
    else
    {
        wbsm4_set_key(key, ks, sizeof(wbsm4_xiao_dykey_context));
        ctx->block = (block128_f)wbsm4_xiao_dykey_decrypt;
    }

    return 1;
}

IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_wbsm4_xiao_dykey_copyctx, PROV_WBSM4_XIAO_DYKEY_CTX)

#define PROV_CIPHER_HW_wbsm4_xiao_dykey_mode(mode)                                    \
    static const PROV_CIPHER_HW wbsm4_xiao_dykey_##mode = {                           \
        cipher_hw_wbsm4_xiao_dykey_initkey,                                           \
        ossl_cipher_hw_generic_##mode,                                             \
        cipher_hw_wbsm4_xiao_dykey_copyctx};                                          \
    const PROV_CIPHER_HW *ossl_prov_cipher_hw_wbsm4_xiao_dykey_##mode(size_t keybits) \
    {                                                                              \
        return &wbsm4_xiao_dykey_##mode;                                              \
    }

PROV_CIPHER_HW_wbsm4_xiao_dykey_mode(cbc);
PROV_CIPHER_HW_wbsm4_xiao_dykey_mode(ecb);
PROV_CIPHER_HW_wbsm4_xiao_dykey_mode(ofb128);
PROV_CIPHER_HW_wbsm4_xiao_dykey_mode(cfb128);
PROV_CIPHER_HW_wbsm4_xiao_dykey_mode(ctr);
#endif