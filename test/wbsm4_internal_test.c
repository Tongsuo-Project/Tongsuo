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

#if !defined(OPENSSL_NO_WBSM4_XIAOLAI) || !defined(OPENSSL_NO_WBSM4_BAIWU) || \
    !defined(OPENSSL_NO_WBSM4_WSISE)
#include "crypto/sm4.h"
#include "crypto/wbsm4.h"
#endif

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
static int test_wbsm4_Xiao_Lai(void)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

    wbsm4_xiaolai_key *wbsm4_key =
                      (wbsm4_xiaolai_key *)malloc(sizeof(wbsm4_xiaolai_key));
    if (wbsm4_key == NULL)
        return 0;
    memset(wbsm4_key, 0, sizeof(wbsm4_xiaolai_key));

    uint8_t block[SM4_BLOCK_SIZE];

    wbsm4_xiaolai_gen(k, wbsm4_key);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiaolai_encrypt(block, block, wbsm4_key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(wbsm4_key);
        return 0;
    }

    unsigned char *keybuf = (unsigned char *)malloc(sizeof(wbsm4_xiaolai_key));
    if (!TEST_ptr_ne(keybuf, NULL)) {
        free(wbsm4_key);
        return 0;
    }

    wbsm4_xiaolai_export_key(wbsm4_key, keybuf);
    wbsm4_xiaolai_set_key(keybuf, wbsm4_key);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_xiaolai_encrypt(block, block, wbsm4_key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname("WBSM4-XIAOLAI-ECB");
    if (!TEST_ptr_ne(cipher, NULL)) {
        free(wbsm4_key);
        return 0;
    }
    int key_length = EVP_CIPHER_get_key_length(cipher);
    if (!TEST_int_eq(key_length, sizeof(wbsm4_xiaolai_key))) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr_ne(cipher_ctx, NULL)) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    int ret = EVP_EncryptInit(cipher_ctx, cipher, (unsigned char *)keybuf, NULL);
    if (!TEST_int_eq(ret, 1)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    int outl = SM4_BLOCK_SIZE;
    memcpy(block, input, SM4_BLOCK_SIZE);
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    free(wbsm4_key);
    free(keybuf);
    return 1;
}
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
static int test_wbsm4_Bai_Wu(void)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

    wbsm4_baiwu_key *wbsm4_key =
                    (wbsm4_baiwu_key *)malloc(sizeof(wbsm4_baiwu_key));
    if (wbsm4_key == NULL)
        return 0;
    memset(wbsm4_key, 0, sizeof(wbsm4_baiwu_key));

    uint8_t block[SM4_BLOCK_SIZE];

    wbsm4_baiwu_gen(k, wbsm4_key);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_baiwu_encrypt(block, block, wbsm4_key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(wbsm4_key);
        return 0;
    }

    unsigned char *keybuf = (unsigned char *)malloc(sizeof(wbsm4_baiwu_key));
    if (!TEST_ptr_ne(keybuf, NULL)) {
        free(wbsm4_key);
        return 0;
    }

    wbsm4_baiwu_export_key(wbsm4_key, keybuf);
    wbsm4_baiwu_set_key(keybuf, wbsm4_key);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_baiwu_encrypt(block, block, wbsm4_key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname("WBSM4-BAIWU-ECB");
    if (!TEST_ptr_ne(cipher, NULL)) {
        free(wbsm4_key);
        return 0;
    }
    int key_length = EVP_CIPHER_get_key_length(cipher);
    if (!TEST_int_eq(key_length, sizeof(wbsm4_baiwu_key))) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr_ne(cipher_ctx, NULL)) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    int ret = EVP_EncryptInit(cipher_ctx, cipher, (unsigned char *)keybuf, NULL);
    if (!TEST_int_eq(ret, 1)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    int outl = SM4_BLOCK_SIZE;
    memcpy(block, input, SM4_BLOCK_SIZE);
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    free(wbsm4_key);
    free(keybuf);
    return 1;
}
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
static int test_wbsm4_WSISE(void)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

    wbsm4_wsise_key *wbsm4_key =
                    (wbsm4_wsise_key *)malloc(sizeof(wbsm4_wsise_key));
    if (wbsm4_key == NULL)
        return 0;
    memset(wbsm4_key, 0, sizeof(wbsm4_wsise_key));

    uint8_t block[SM4_BLOCK_SIZE];

    wbsm4_wsise_gen(k, wbsm4_key);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_wsise_encrypt(block, block, wbsm4_key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(wbsm4_key);
        return 0;
    }

    unsigned char *keybuf = (unsigned char *)malloc(sizeof(wbsm4_wsise_key));
    if (!TEST_ptr_ne(keybuf, NULL)) {
        free(wbsm4_key);
        return 0;
    }

    wbsm4_wsise_export_key(wbsm4_key, keybuf);
    wbsm4_wsise_set_key(keybuf, wbsm4_key);

    memcpy(block, input, SM4_BLOCK_SIZE);
    wbsm4_wsise_encrypt(block, block, wbsm4_key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname("WBSM4-WSISE-ECB");
    if (!TEST_ptr_ne(cipher, NULL)) {
        free(wbsm4_key);
        return 0;
    }
    int key_length = EVP_CIPHER_get_key_length(cipher);
    if (!TEST_int_eq(key_length, sizeof(wbsm4_wsise_key))) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr_ne(cipher_ctx, NULL)) {
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    int ret = EVP_EncryptInit(cipher_ctx, cipher, (unsigned char *)keybuf, NULL);
    if (!TEST_int_eq(ret, 1)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    int outl = SM4_BLOCK_SIZE;
    memcpy(block, input, SM4_BLOCK_SIZE);
    ret = EVP_EncryptUpdate(cipher_ctx, block, &outl, block, SM4_BLOCK_SIZE);
    if (!TEST_int_eq(ret, 1) && !TEST_int_eq(outl, 16)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(wbsm4_key);
        free(keybuf);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    free(wbsm4_key);
    free(keybuf);
    return 1;
}
#endif /* OPENSSL_NO_WBSM4_WSISE */

int setup_tests(void)
{
#ifndef OPENSSL_NO_WBSM4_XIAOLAI
    ADD_TEST(test_wbsm4_Xiao_Lai);
#endif
#ifndef OPENSSL_NO_WBSM4_BAIWU
    ADD_TEST(test_wbsm4_Bai_Wu);
#endif
#ifndef OPENSSL_NO_WBSM4_WSISE
    ADD_TEST(test_wbsm4_WSISE);
#endif
    return 1;
}
