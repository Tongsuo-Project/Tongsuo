/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Internal tests for the WBSM4 module.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "testutil.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
#include "crypto/sm4.h"
#include "crypto/wbsm4.h"

#define BUF_SIZE (1024)

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
    
    static uint8_t block[SM4_BLOCK_SIZE];
    
    static int result = 0;
    wbsm4_xiao_dykey_context *ctx = NULL;
    wbsm4_xiao_dykey_ctxrk *ctxrk = NULL;
    wbsm4_xiao_dykey_context *ctx_decrypt = NULL;
    wbsm4_xiao_dykey_ctxrk *ctxrk_decrypt = NULL;

    ctx = (wbsm4_xiao_dykey_context *)malloc(sizeof(wbsm4_xiao_dykey_context));
    if (ctx == NULL)
        goto end;
    ctxrk = (wbsm4_xiao_dykey_ctxrk *)malloc(sizeof(wbsm4_xiao_dykey_ctxrk));
    if (ctxrk == NULL) {
        goto end;
    }
    memset(ctx, 0, sizeof(wbsm4_xiao_dykey_context));
    ctx->mode = WBSM4_ENCRYPT_MODE;

    wbsm4_xiao_dykey_gen(k, ctx, ctxrk);
    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiao_dykey_encrypt(block, block, ctx);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        goto end;
    }

    // decrypt
    ctx_decrypt = (wbsm4_xiao_dykey_context *)malloc(sizeof(wbsm4_xiao_dykey_context));
    if (ctx_decrypt == NULL) {
        goto end;
    }
    ctx_decrypt->mode = WBSM4_DECRYPT_MODE;
    ctxrk_decrypt = (wbsm4_xiao_dykey_ctxrk *)malloc(sizeof(wbsm4_xiao_dykey_ctxrk));
    if (ctxrk_decrypt == NULL) {
        goto end;
    }

    wbsm4_xiao_dykey_gen(k, ctx_decrypt, ctxrk_decrypt);

    wbsm4_xiao_dykey_decrypt(block, block, ctx_decrypt);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE)) {
        goto end;
    }

    //update key without transfer the whole LUT
    k[0] = 0xff;
    uint32_t wbrk[SM4_KEY_SCHEDULE];
    wbsm4_xiao_dykey_key2wbrk(k, ctxrk, wbrk);

    wbsm4_xiao_dykey_update_wbrk(ctx, wbrk);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiao_dykey_encrypt(block, block, ctx);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_new_key, SM4_BLOCK_SIZE)) {
        goto end;
    }

    wbsm4_xiao_dykey_key2wbrk(k, ctxrk_decrypt, wbrk);

    wbsm4_xiao_dykey_update_wbrk(ctx_decrypt, wbrk);

    wbsm4_xiao_dykey_decrypt(block, block, ctx_decrypt);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE)) {
        goto end;
    }

    result = 1;

end:
    if (ctx) free(ctx);
    if (ctxrk) free(ctxrk);
    if (ctx_decrypt) free(ctx_decrypt);
    if (ctxrk_decrypt) free(ctxrk_decrypt);
    return result;
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
    static int result = 0;
    int outl = SM4_BLOCK_SIZE;
    unsigned char block[SM4_BLOCK_SIZE];
    int mode = EVP_KDF_WBSM4KDF_MODE_ENCRYPT;

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char *wbsm4ctx = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    uint8_t *wbrk_buf = NULL;

    kdf = EVP_KDF_fetch(NULL, "WBSM4KDF", NULL);
    if (!TEST_ptr_ne(kdf, NULL)) {
        goto end;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    if (!TEST_ptr_ne(kctx, NULL)) {
        goto end;
    }

    size_t len_wbsm4ctx = EVP_KDF_CTX_get_kdf_size(kctx);
    if (!TEST_int_eq(len_wbsm4ctx, sizeof(wbsm4_xiao_dykey_context))) {
        goto end;
    }

    wbsm4ctx = (unsigned char *)OPENSSL_malloc(len_wbsm4ctx);
    if (!TEST_ptr_ne(wbsm4ctx, NULL)) {
        goto end;
    }

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, k, SM4_BLOCK_SIZE);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(kctx, wbsm4ctx, len_wbsm4ctx, params);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname("WBSM4-XIAO-DYKEY-ECB");
    if (!TEST_ptr_ne(cipher, NULL)) {
        goto end;
    }
    int key_length = EVP_CIPHER_get_key_length(cipher);
    if (!TEST_int_eq(key_length, sizeof(wbsm4_xiao_dykey_context))) {
        goto end;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr_ne(cipher_ctx, NULL)) {
        goto end;
    }

    ret = EVP_EncryptInit(cipher_ctx, cipher, (unsigned char *)wbsm4ctx, NULL);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    memcpy(block, input, SM4_BLOCK_SIZE);
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        goto end;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        goto end;
    }

    // update key
    k[0] = 0xff;
    mode = EVP_KDF_WBSM4KDF_MODE_UPDATE_KEY;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, k, SM4_BLOCK_SIZE);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_end();
    wbrk_buf = (uint8_t *)OPENSSL_malloc(SM4_KEY_SCHEDULE * sizeof(uint32_t));
    if (!TEST_ptr_ne(wbrk_buf, NULL)) {
        goto end;
    }

    ret = EVP_KDF_derive(kctx, wbrk_buf, SM4_KEY_SCHEDULE * sizeof(uint32_t), params);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, wbrk_buf, SM4_KEY_SCHEDULE * sizeof(uint32_t));
    params[1] = OSSL_PARAM_construct_end();
    ret = EVP_CIPHER_CTX_set_params(cipher_ctx, params); 
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    memcpy(block, input, SM4_BLOCK_SIZE);
    outl = SM4_BLOCK_SIZE;
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        goto end;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_new_key, SM4_BLOCK_SIZE)) {
        goto end;
    }

    result = 1;

end:
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    if (wbsm4ctx) OPENSSL_free(wbsm4ctx);
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    if (wbrk_buf) OPENSSL_free(wbrk_buf);
    return result;
}

/*
随机的密钥和输入，对比SM4白盒加解密和标准SM4的加解密结果应该一致
*/
static int test_wbsm4_random_encrypt(void)
{
    static uint8_t k[SM4_BLOCK_SIZE] = {0};
    static uint8_t iv[SM4_BLOCK_SIZE] = {0};
    static uint8_t plaintext[BUF_SIZE] = {0};
    static uint8_t ciphertext_sm4[BUF_SIZE + SM4_BLOCK_SIZE] = {0};
    static uint8_t ciphertext_wbsm4[BUF_SIZE + SM4_BLOCK_SIZE] = {0};

    static uint8_t k_old[SM4_BLOCK_SIZE] = {0};
    memcpy(k_old, k, SM4_BLOCK_SIZE);

    RAND_bytes(k, sizeof(k));
    RAND_bytes(iv, sizeof(iv));
    RAND_bytes(plaintext, sizeof(plaintext));

    static int ret = 0;
    static int result = 0;
    int outl;
    int mode = EVP_KDF_WBSM4KDF_MODE_ENCRYPT;

    int ciphertext_len_sm4 = 0;
    int ciphertext_len_wbsm4 = 0;
    EVP_CIPHER_CTX *cctx_sm4 = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char *wbsm4ctx = NULL;
    EVP_CIPHER_CTX *cctx_wbsm4 = NULL;

    /* sm4 */
    const EVP_CIPHER *cipher_sm4 = EVP_get_cipherbyname("SM4-CBC");
    cctx_sm4 = EVP_CIPHER_CTX_new();
    ret = EVP_EncryptInit(cctx_sm4, cipher_sm4, k, iv);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }
    EVP_EncryptUpdate(cctx_sm4, ciphertext_sm4, &outl, plaintext, BUF_SIZE);
    ciphertext_len_sm4 = outl;
    EVP_EncryptFinal(cctx_sm4, ciphertext_sm4 + outl, &outl);
    ciphertext_len_sm4 += outl;

    /* wbsm4 */
    kdf = EVP_KDF_fetch(NULL, "WBSM4KDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    size_t len_wbsm4ctx = EVP_KDF_CTX_get_kdf_size(kctx);
    wbsm4ctx = (unsigned char *)OPENSSL_malloc(len_wbsm4ctx);
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, k, SM4_BLOCK_SIZE);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_end();
    EVP_KDF_derive(kctx, wbsm4ctx, len_wbsm4ctx, params);

    const EVP_CIPHER *cipher_wbsm4 = EVP_get_cipherbyname("WBSM4-XIAO-DYKEY-CBC");
    cctx_wbsm4 = EVP_CIPHER_CTX_new();
    ret = EVP_EncryptInit(cctx_wbsm4, cipher_wbsm4, (unsigned char *)wbsm4ctx, iv);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }
    EVP_EncryptUpdate(cctx_wbsm4, ciphertext_wbsm4, &outl, plaintext, BUF_SIZE);
    ciphertext_len_wbsm4 = outl;
    EVP_EncryptFinal(cctx_wbsm4, ciphertext_wbsm4 + outl, &outl);
    ciphertext_len_wbsm4 += outl;

    /* comparison */
    if (!TEST_int_eq(ciphertext_len_sm4, ciphertext_len_wbsm4)) {
        goto end;
    }
    if (!TEST_mem_eq(ciphertext_sm4, ciphertext_len_sm4, ciphertext_wbsm4, ciphertext_len_wbsm4)) {
        goto end;
    }

    result = 1;

end:
    if (cctx_sm4) EVP_CIPHER_CTX_free(cctx_sm4);
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    if (wbsm4ctx) OPENSSL_free(wbsm4ctx);
    if (cctx_wbsm4) EVP_CIPHER_CTX_free(cctx_wbsm4);
    return result;
}

/*
同一个原始密钥，2次生成白盒，比较白盒查找表
*/
static int test_wbsm4_context(void)
{
    static uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static int ret = 0;
    static int result = 0;
    int mode = EVP_KDF_WBSM4KDF_MODE_ENCRYPT;

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char *wbsm4ctx1 = NULL;
    unsigned char *wbsm4ctx2 = NULL;

    kdf = EVP_KDF_fetch(NULL, "WBSM4KDF", NULL);
    if (!TEST_ptr_ne(kdf, NULL)) {
        goto end;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    if (!TEST_ptr_ne(kctx, NULL)) {
        goto end;
    }

    size_t len_wbsm4ctx = EVP_KDF_CTX_get_kdf_size(kctx);
    if (!TEST_int_eq(len_wbsm4ctx, sizeof(wbsm4_xiao_dykey_context))) {
        goto end;
    }

    /* first wbsm4ctx */
    wbsm4ctx1 = (unsigned char *)OPENSSL_malloc(len_wbsm4ctx);
    if (!TEST_ptr_ne(wbsm4ctx1, NULL)) {
        goto end;
    }

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, k, SM4_BLOCK_SIZE);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(kctx, wbsm4ctx1, len_wbsm4ctx, params);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    /* second wbsm4ctx */
    wbsm4ctx2 = (unsigned char *)OPENSSL_malloc(len_wbsm4ctx);
    if (!TEST_ptr_ne(wbsm4ctx2, NULL)) {
        goto end;
    }

    ret = EVP_KDF_derive(kctx, wbsm4ctx2, len_wbsm4ctx, params);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    if (!TEST_mem_ne(wbsm4ctx1, len_wbsm4ctx, wbsm4ctx2, len_wbsm4ctx)) {
        goto end;
    }

    result = 1;

end:
    if (kdf) EVP_KDF_free(kdf);
    if (kctx) EVP_KDF_CTX_free(kctx);
    if (wbsm4ctx1) OPENSSL_free(wbsm4ctx1);
    if (wbsm4ctx2) OPENSSL_free(wbsm4ctx2);
    return result;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
    ADD_TEST(test_wbsm4_xiao_dykey);
    ADD_TEST(test_EVP_wbsm4_xiao_dykey);
    ADD_TEST(test_wbsm4_random_encrypt);
    ADD_TEST(test_wbsm4_context);
#endif
    return 1;
}
