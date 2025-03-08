/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
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

#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include "testutil.h"

#if !defined(OPENSSL_NO_WBSM4_XIAO_STKEY) || !defined(OPENSSL_WBSM4_JIN_STKEY) \
|| !defined(OPENSSL_NO_WBSM4_XIAO_DYKEY)
#include "crypto/sm4.h"
#include "crypto/wbsm4.h"
#endif

#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
static int test_wbsm4_xiao_stkey(void)
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

    // unsigned char *keybuf = (unsigned char *)malloc(sizeof(wbsm4_xiao_stkey_context));
    // if (!TEST_ptr_ne(keybuf, NULL)) {
    //     free(ctx);
    //     return 0;
    // }


    for (i = 0; i != 999999; ++i)
        wbsm4_xiao_stkey_encrypt(block, block, ctx);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_iter, SM4_BLOCK_SIZE)) {
        free(ctx);
        return 0;
    }
    
    wbsm4_xiao_stkey_context *ctx_decrypt =
    (wbsm4_xiao_stkey_context *)malloc(sizeof(wbsm4_xiao_stkey_context));
    if (ctx == NULL)
        return 0;
    memset(ctx_decrypt, 0, sizeof(wbsm4_xiao_stkey_context));
    ctx_decrypt->mode = WBSM4_DECRYPT_MODE;

    wbsm4_xiao_stkey_gen(k, ctx_decrypt);

    for (i = 0; i != 1000000; ++i)
        wbsm4_xiao_stkey_decrypt(block, block, ctx_decrypt);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE))
        return 0;

    return 1;

    // wbsm4_xiao_stkey_export_key(ctx, keybuf);
    // wbsm4_xiao_stkey_set_key(keybuf, ctx);

    // memcpy(block, input, SM4_BLOCK_SIZE);
    // wbsm4_xiao_stkey_encrypt(block, block, ctx);
    // if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
    //     free(ctx);
    //     free(keybuf);
    //     return 0;
    // }

    // const EVP_CIPHER *cipher = EVP_get_cipherbyname("WBSM4-XIAO-STKEY-ECB");
    // if (!TEST_ptr_ne(cipher, NULL)) {
    //     free(ctx);
    //     return 0;
    // }
    // int key_length = EVP_CIPHER_get_key_length(cipher);
    // if (!TEST_int_eq(key_length, sizeof(wbsm4_xiao_stkey_context))) {
    //     free(ctx);
    //     free(keybuf);
    //     return 0;
    // }

    // EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    // if (!TEST_ptr_ne(cipher_ctx, NULL)) {
    //     free(ctx);
    //     free(keybuf);
    //     return 0;
    // }

    // int ret = EVP_EncryptInit(cipher_ctx, cipher, (unsigned char *)keybuf, NULL);
    // if (!TEST_int_eq(ret, 1)) {
    //     EVP_CIPHER_CTX_free(cipher_ctx);
    //     free(ctx);
    //     free(keybuf);
    //     return 0;
    // }

    // int outl = SM4_BLOCK_SIZE;
    // memcpy(block, input, SM4_BLOCK_SIZE);
    // ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    // if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
    //     EVP_CIPHER_CTX_free(cipher_ctx);
    //     free(ctx);
    //     free(keybuf);
    //     return 0;
    // }
    // if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
    //     EVP_CIPHER_CTX_free(cipher_ctx);
    //     free(ctx);
    //     free(keybuf);
    //     return 0;
    // }

    // EVP_CIPHER_CTX_free(cipher_ctx);
    // free(ctx);
    // free(keybuf);
    // return 1;
}
#endif

#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
static int test_wbsm4_jin_stkey(void)
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
    if (ctx == NULL)
        return 0;
    memset(ctx_decrypt, 0, sizeof(wbsm4_jin_stkey_context));
    ctx_decrypt->mode = WBSM4_DECRYPT_MODE;

    wbsm4_jin_stkey_gen(k, ctx_decrypt);

    for (i = 0; i != 1000000; ++i)
        wbsm4_jin_stkey_decrypt(block, block, ctx_decrypt);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE))
        return 0;

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
    if (ctxrk == NULL)
        return 0;
    memset(ctx, 0, sizeof(wbsm4_xiao_dykey_context));
    ctx->mode = WBSM4_ENCRYPT_MODE;

    wbsm4_xiao_dykey_gen(k, ctx, ctxrk);
    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiao_dykey_encrypt(block, block, ctx);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(ctx);
        return 0;
    }

    // decrypt
    wbsm4_xiao_dykey_context *ctx_decrypt = (wbsm4_xiao_dykey_context *)malloc(sizeof(wbsm4_xiao_dykey_context));
    if (ctx_decrypt == NULL)
        return 0;
    ctx_decrypt->mode = WBSM4_DECRYPT_MODE;
    wbsm4_xiao_dykey_ctxrk *ctxrk_decrypt = (wbsm4_xiao_dykey_ctxrk *)malloc(sizeof(wbsm4_xiao_dykey_ctxrk));
    if (ctxrk_decrypt == NULL)
        return 0;

    wbsm4_xiao_dykey_gen(k, ctx_decrypt, ctxrk_decrypt);

    wbsm4_xiao_dykey_decrypt(block, block, ctx_decrypt);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE))
        return 0;

    //update key without transfer the whole LUT
    k[0] = 0xff;
    uint32_t wbrk[32];
    wbsm4_xiao_dykey_key2wbrk(k, ctxrk, wbrk);

    wbsm4_xiao_dykey_update_wbrk(ctx, wbrk);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiao_dykey_encrypt(block, block, ctx);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_new_key, SM4_BLOCK_SIZE))
        return 0;

    wbsm4_xiao_dykey_key2wbrk(k, ctxrk_decrypt, wbrk);

    wbsm4_xiao_dykey_update_wbrk(ctx_decrypt, wbrk);

    wbsm4_xiao_dykey_decrypt(block, block, ctx_decrypt);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE))
        return 0;

    return 1;

}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
    ADD_TEST(test_wbsm4_xiao_stkey);
#endif
#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
    ADD_TEST(test_wbsm4_jin_stkey);
#endif
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
    ADD_TEST(test_wbsm4_xiao_dykey);
#endif
}
