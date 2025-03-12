/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal tests for the WBSM4 module.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "testutil.h"

#if !defined(OPENSSL_NO_WBSM4_XIAO_STKEY) || !defined(OPENSSL_NO_WBSM4_JIN_STKEY) \
|| !defined(OPENSSL_NO_WBSM4_XIAO_DYKEY)
#include "crypto/sm4.h"
#include "crypto/wbsm4.h"
#endif

#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
static int test_wbsm4_xiao_stkey(void)
{
    static uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    /*
     * This test vector comes from Example 2 from GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     * After 1,000,000 iterations.
     */
    static const uint8_t expected_iter[SM4_BLOCK_SIZE] = {
        0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
        0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
    };

    int i;
    wbsm4_xiao_stkey_context *ctx = (wbsm4_xiao_stkey_context *)malloc(sizeof(wbsm4_xiao_stkey_context));
    if (ctx == NULL)
        return 0;
    memset(ctx, 0, sizeof(wbsm4_xiao_stkey_context));
    ctx->mode = WBSM4_ENCRYPT_MODE;

    uint8_t block[SM4_BLOCK_SIZE];

    wbsm4_xiao_stkey_gen(k, ctx);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiao_stkey_encrypt(block, block, ctx);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(ctx);
        return 0;
    }

    for (i = 0; i != 999999; ++i)
        wbsm4_xiao_stkey_encrypt(block, block, ctx);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_iter, SM4_BLOCK_SIZE)) {
        free(ctx);
        return 0;
    }
    
    wbsm4_xiao_stkey_context *ctx_decrypt =
    (wbsm4_xiao_stkey_context *)malloc(sizeof(wbsm4_xiao_stkey_context));
    if (ctx_decrypt == NULL) {
        free(ctx);
        return 0;
    }
    memset(ctx_decrypt, 0, sizeof(wbsm4_xiao_stkey_context));
    ctx_decrypt->mode = WBSM4_DECRYPT_MODE;

    wbsm4_xiao_stkey_gen(k, ctx_decrypt);

    for (i = 0; i != 1000000; ++i)
        wbsm4_xiao_stkey_decrypt(block, block, ctx_decrypt);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE)) {
        free(ctx);
        free(ctx_decrypt);
        return 0;
    }

    free(ctx);
    free(ctx_decrypt);
    return 1;
}

static int test_EVP_wbsm4_xiao_stkey(void)
{
    static uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };
    static int ret = 0;
    int outl = SM4_BLOCK_SIZE;
    unsigned char block[SM4_BLOCK_SIZE];
    int mode = WBSM4_ENCRYPT_MODE;

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, k, SM4_BLOCK_SIZE);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, "wbsm4-xiao-stkey", 0);
    params[2] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[3] = OSSL_PARAM_construct_end();

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "WBSM4KDF", NULL);
    if (!TEST_ptr_ne(kdf, NULL)) {
        return 0;
    }
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!TEST_ptr_ne(kctx, NULL)) {
        EVP_KDF_free(kdf);
        return 0;
    }

    ret = EVP_KDF_CTX_set_params(kctx, params);
    if (!TEST_int_eq(ret, 1)) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    size_t len_wbsm4ctx = EVP_KDF_CTX_get_kdf_size(kctx);
    if (!TEST_int_eq(len_wbsm4ctx, sizeof(wbsm4_xiao_stkey_context))) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    unsigned char *wbsm4ctx = (unsigned char *)OPENSSL_malloc(len_wbsm4ctx);
    if (!TEST_ptr_ne(wbsm4ctx, NULL)) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    ret = EVP_KDF_derive(kctx, wbsm4ctx, len_wbsm4ctx, NULL);
    if (!TEST_int_eq(ret, 1)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname("WBSM4-XIAO-STKEY-ECB");
    if (!TEST_ptr_ne(cipher, NULL)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }
    int key_length = EVP_CIPHER_get_key_length(cipher);
    if (!TEST_int_eq(key_length, sizeof(wbsm4_xiao_stkey_context))) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr_ne(cipher_ctx, NULL)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    ret = EVP_EncryptInit(cipher_ctx, cipher, (unsigned char *)wbsm4ctx, NULL);
    if (!TEST_int_eq(ret, 1)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    memcpy(block, input, SM4_BLOCK_SIZE);
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    OPENSSL_free(wbsm4ctx);
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return 1;
}

#endif

#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
static int test_wbsm4_jin_stkey(void)
{
    static uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    /*
     * This test vector comes from Example 2 from GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     * After 1,000,000 iterations.
     */
    static const uint8_t expected_iter[SM4_BLOCK_SIZE] = {
        0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
        0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
    };

    int i;
    wbsm4_jin_stkey_context *ctx = (wbsm4_jin_stkey_context *)malloc(sizeof(wbsm4_jin_stkey_context));
    if (ctx == NULL)
        return 0;
    memset(ctx, 0, sizeof(wbsm4_jin_stkey_context));
    ctx->mode = WBSM4_ENCRYPT_MODE;

    uint8_t block[SM4_BLOCK_SIZE];

    wbsm4_jin_stkey_gen(k, ctx);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_jin_stkey_encrypt(block, block, ctx);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(ctx);
        return 0;
    }

    for (i = 0; i != 999999; ++i)
        wbsm4_jin_stkey_encrypt(block, block, ctx);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_iter, SM4_BLOCK_SIZE)) {
        free(ctx);
        return 0;
    }

    wbsm4_jin_stkey_context *ctx_decrypt =
    (wbsm4_jin_stkey_context *)malloc(sizeof(wbsm4_jin_stkey_context));
    if (ctx_decrypt == NULL) {
        free(ctx);
        return 0;
    }
    memset(ctx_decrypt, 0, sizeof(wbsm4_jin_stkey_context));
    ctx_decrypt->mode = WBSM4_DECRYPT_MODE;

    wbsm4_jin_stkey_gen(k, ctx_decrypt);

    for (i = 0; i != 1000000; ++i)
        wbsm4_jin_stkey_decrypt(block, block, ctx_decrypt);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE)) {
        free(ctx);
        free(ctx_decrypt);
        return 0;
    }

    free(ctx);
    free(ctx_decrypt);
    return 1;

}

static int test_EVP_wbsm4_jin_stkey(void)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };
    static int ret = 0;
    int outl = SM4_BLOCK_SIZE;
    unsigned char block[SM4_BLOCK_SIZE];
    int mode = WBSM4_ENCRYPT_MODE;

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, k, SM4_BLOCK_SIZE);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, "wbsm4-jin-stkey", 0);
    params[2] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[3] = OSSL_PARAM_construct_end();

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "WBSM4KDF", NULL);
    if (!TEST_ptr_ne(kdf, NULL)) {
        return 0;
    }
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!TEST_ptr_ne(kctx, NULL)) {
        EVP_KDF_free(kdf);
        return 0;
    }

    ret = EVP_KDF_CTX_set_params(kctx, params);
    if (!TEST_int_eq(ret, 1)) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    size_t len_wbsm4ctx = EVP_KDF_CTX_get_kdf_size(kctx);
    if (!TEST_int_eq(len_wbsm4ctx, sizeof(wbsm4_jin_stkey_context))) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    unsigned char *wbsm4ctx = (unsigned char *)OPENSSL_malloc(len_wbsm4ctx);
    if (!TEST_ptr_ne(wbsm4ctx, NULL)) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    ret = EVP_KDF_derive(kctx, wbsm4ctx, len_wbsm4ctx, NULL);
    if (!TEST_int_eq(ret, 1)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname("WBSM4-JIN-STKEY-ECB");
    if (!TEST_ptr_ne(cipher, NULL)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }
    int key_length = EVP_CIPHER_get_key_length(cipher);
    if (!TEST_int_eq(key_length, sizeof(wbsm4_jin_stkey_context))) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr_ne(cipher_ctx, NULL)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    ret = EVP_EncryptInit(cipher_ctx, cipher, (unsigned char *)wbsm4ctx, NULL);
    if (!TEST_int_eq(ret, 1)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    memcpy(block, input, SM4_BLOCK_SIZE);
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    OPENSSL_free(wbsm4ctx);
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return 1;
}

#endif

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
static int test_wbsm4_xiao_dykey(void)
{
    static uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };
    
    static const uint8_t expected_new_key[SM4_BLOCK_SIZE] = {
        0xbd, 0x0c, 0x54, 0xe5, 0x21, 0x92, 0x10, 0x2b, 
        0x7a, 0x6c, 0x17, 0x58, 0x96, 0xe2, 0x5c, 0x92
    };
    
    uint8_t block[SM4_BLOCK_SIZE];

    wbsm4_xiao_dykey_context *ctx = (wbsm4_xiao_dykey_context *)malloc(sizeof(wbsm4_xiao_dykey_context));
    if (ctx == NULL)
        return 0;
    wbsm4_xiao_dykey_ctxrk *ctxrk = (wbsm4_xiao_dykey_ctxrk *)malloc(sizeof(wbsm4_xiao_dykey_ctxrk));
    if (ctxrk == NULL) {
        free(ctx);
        return 0;
    }
    memset(ctx, 0, sizeof(wbsm4_xiao_dykey_context));
    ctx->mode = WBSM4_ENCRYPT_MODE;

    wbsm4_xiao_dykey_gen(k, ctx, ctxrk);
    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiao_dykey_encrypt(block, block, ctx);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(ctx);
        free(ctxrk);
        return 0;
    }

    // decrypt
    wbsm4_xiao_dykey_context *ctx_decrypt = (wbsm4_xiao_dykey_context *)malloc(sizeof(wbsm4_xiao_dykey_context));
    if (ctx_decrypt == NULL) {
        free(ctx);
        free(ctxrk);
        return 0;
    }
    ctx_decrypt->mode = WBSM4_DECRYPT_MODE;
    wbsm4_xiao_dykey_ctxrk *ctxrk_decrypt = (wbsm4_xiao_dykey_ctxrk *)malloc(sizeof(wbsm4_xiao_dykey_ctxrk));
    if (ctxrk_decrypt == NULL) {
        free(ctx);
        free(ctxrk);
        free(ctx_decrypt);
        return 0;
    }

    wbsm4_xiao_dykey_gen(k, ctx_decrypt, ctxrk_decrypt);

    wbsm4_xiao_dykey_decrypt(block, block, ctx_decrypt);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE)) {
        free(ctx);
        free(ctxrk);
        free(ctx_decrypt);
        free(ctxrk_decrypt);
        return 0;
    }

    //update key without transfer the whole LUT
    k[0] = 0xff;
    uint32_t wbrk[32];
    wbsm4_xiao_dykey_key2wbrk(k, ctxrk, wbrk);

    wbsm4_xiao_dykey_update_wbrk(ctx, wbrk);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiao_dykey_encrypt(block, block, ctx);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_new_key, SM4_BLOCK_SIZE)) {
        free(ctx);
        free(ctxrk);
        free(ctx_decrypt);
        free(ctxrk_decrypt);
        return 0;
    }

    wbsm4_xiao_dykey_key2wbrk(k, ctxrk_decrypt, wbrk);

    wbsm4_xiao_dykey_update_wbrk(ctx_decrypt, wbrk);

    wbsm4_xiao_dykey_decrypt(block, block, ctx_decrypt);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE)) {
        free(ctx);
        free(ctxrk);
        free(ctx_decrypt);
        free(ctxrk_decrypt);
        return 0;
    }

    free(ctx);
    free(ctxrk);
    free(ctx_decrypt);
    free(ctxrk_decrypt);
    return 1;
}

static int test_EVP_wbsm4_xiao_dykey(void)
{
    static uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    static const uint8_t expected_new_key[SM4_BLOCK_SIZE] = {
        0xbd, 0x0c, 0x54, 0xe5, 0x21, 0x92, 0x10, 0x2b, 
        0x7a, 0x6c, 0x17, 0x58, 0x96, 0xe2, 0x5c, 0x92
    };

    static int ret = 0;
    int outl = SM4_BLOCK_SIZE;
    unsigned char block[SM4_BLOCK_SIZE];
    int mode = WBSM4_ENCRYPT_MODE;

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, k, SM4_BLOCK_SIZE);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, "wbsm4-xiao-dykey", 0);
    params[2] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[3] = OSSL_PARAM_construct_end();

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "WBSM4KDF", NULL);
    if (!TEST_ptr_ne(kdf, NULL)) {
        return 0;
    }
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!TEST_ptr_ne(kctx, NULL)) {
        EVP_KDF_free(kdf);
        return 0;
    }

    ret = EVP_KDF_CTX_set_params(kctx, params);
    if (!TEST_int_eq(ret, 1)) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    size_t len_wbsm4ctx = EVP_KDF_CTX_get_kdf_size(kctx);
    if (!TEST_int_eq(len_wbsm4ctx, sizeof(wbsm4_xiao_dykey_context))) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    unsigned char *wbsm4ctx = (unsigned char *)OPENSSL_malloc(len_wbsm4ctx);
    if (!TEST_ptr_ne(wbsm4ctx, NULL)) {
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    ret = EVP_KDF_derive(kctx, wbsm4ctx, len_wbsm4ctx, NULL);
    if (!TEST_int_eq(ret, 1)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname("WBSM4-XIAO-DYKEY-ECB");
    if (!TEST_ptr_ne(cipher, NULL)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }
    int key_length = EVP_CIPHER_get_key_length(cipher);
    if (!TEST_int_eq(key_length, sizeof(wbsm4_xiao_dykey_context))) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr_ne(cipher_ctx, NULL)) {
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    ret = EVP_EncryptInit(cipher_ctx, cipher, (unsigned char *)wbsm4ctx, NULL);
    if (!TEST_int_eq(ret, 1)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    memcpy(block, input, SM4_BLOCK_SIZE);
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    // update key
    k[0] = 0xff;
    int update_key = 1;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, k, SM4_BLOCK_SIZE);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_WBSM4_UPDATE_KEY, &update_key);
    params[2] = OSSL_PARAM_construct_end();
    uint8_t *wbrk_buf = (uint8_t *)OPENSSL_malloc(32 * sizeof(uint32_t));
    if (!TEST_ptr_ne(wbrk_buf, NULL)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    ret = EVP_KDF_derive(kctx, wbrk_buf, 32 * sizeof(uint32_t), params);
    if (!TEST_int_eq(ret, 1)) {
        OPENSSL_free(wbrk_buf);
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, wbrk_buf, 32 * sizeof(uint32_t));
    params[1] = OSSL_PARAM_construct_end();
    ret = EVP_CIPHER_CTX_set_params(cipher_ctx, params); 
    // ret = EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_WBSM4_UPDATE_KEY, 32 * sizeof(uint32_t), wbrk_buf);
    if (!TEST_int_eq(ret, 1)) {
        OPENSSL_free(wbrk_buf);
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    memcpy(block, input, SM4_BLOCK_SIZE);
    outl = SM4_BLOCK_SIZE;
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbrk_buf);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_new_key, SM4_BLOCK_SIZE)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        OPENSSL_free(wbrk_buf);
        OPENSSL_free(wbsm4ctx);
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(kctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    OPENSSL_free(wbrk_buf);
    OPENSSL_free(wbsm4ctx);
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return 1;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
    ADD_TEST(test_wbsm4_xiao_stkey);
    ADD_TEST(test_EVP_wbsm4_xiao_stkey);
#endif
#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
    ADD_TEST(test_wbsm4_jin_stkey);
    ADD_TEST(test_EVP_wbsm4_jin_stkey);
#endif
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
    ADD_TEST(test_wbsm4_xiao_dykey);
    ADD_TEST(test_EVP_wbsm4_xiao_dykey);
#endif
    return 1;
}
