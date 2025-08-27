/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some engine deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <openssl/opensslconf.h>

#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "testutil.h"

/* Use a buffer size which is not aligned to block size */
#define BUFFER_SIZE     17

#ifndef OPENSSL_NO_ENGINE
static ENGINE *e;

static int test_afalg_aes_cbc(int keysize_idx)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    const unsigned char *enc_result = NULL;
    int encl, encf, decl, decf;
    int ret = 0;
    static const unsigned char key[] =
        "\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06"
        "\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06";
    static const unsigned char iv[] =
        "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41";
    /* input = "Single block msg\n" 17 Bytes*/

    static const unsigned char in[BUFFER_SIZE] = {
        0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x6d, 0x73, 0x67, 0x0a
    };
    
    static const unsigned char encresult_128[BUFFER_SIZE] = {
        0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8, 0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77, 0x18, 0x1a, 0x2d
    };
    
    static const unsigned char encresult_192[BUFFER_SIZE] = {
        0xf7, 0xe4, 0x26, 0xd1, 0xd5, 0x4f, 0x8f, 0x39, 0xb1, 0x9e, 0xe0, 0xdf, 0x61, 0xb9, 0xc2, 0x55, 0xeb
    };
    
    static const unsigned char encresult_256[BUFFER_SIZE] = {
        0xa0, 0x76, 0x85, 0xfd, 0xc1, 0x65, 0x71, 0x9d, 0xc7, 0xe9, 0x13, 0x6e, 0xae, 0x55, 0x49, 0xb4, 0x13
    };

    

#ifdef OSSL_SANITIZE_MEMORY
    /*
     * Initialise the encryption & decryption buffers to pacify the memory
     * sanitiser.  The sanitiser doesn't know that this memory is modified
     * by the engine, this tells it that all is good.
     */
    OPENSSL_cleanse(ebuf, sizeof(ebuf));
    OPENSSL_cleanse(dbuf, sizeof(dbuf));
#endif

    switch (keysize_idx) {
        case 0:
            cipher = EVP_aes_128_cbc();
            enc_result = &encresult_128[0];
            break;
        case 1:
            cipher = EVP_aes_192_cbc();
            enc_result = &encresult_192[0];
            break;
        case 2:
            cipher = EVP_aes_256_cbc();
            enc_result = &encresult_256[0];
            break;
        default:
            cipher = NULL;
    }
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
            return 0;

    if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1))
            || !TEST_true(EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE))
            || !TEST_true(EVP_CipherFinal_ex(ctx, ebuf + encl, &encf)))
        goto end;
    encl += encf;

    if (!TEST_mem_eq(enc_result, BUFFER_SIZE, ebuf, BUFFER_SIZE))
        goto end;

    if (!TEST_true(EVP_CIPHER_CTX_reset(ctx))
            || !TEST_true(EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0))
            || !TEST_true(EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl))
            || !TEST_true(EVP_CipherFinal_ex(ctx, dbuf + decl, &decf)))
        goto end;
    decl += decf;

    if (!TEST_int_eq(decl, BUFFER_SIZE)
            || !TEST_mem_eq(dbuf, BUFFER_SIZE, in, BUFFER_SIZE))
        goto end;

    ret = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int test_pr16743(void)
{
    int ret = 0;
    const EVP_CIPHER * cipher;
    EVP_CIPHER_CTX *ctx;

    if (!TEST_true(ENGINE_init(e)))
        return 0;
    cipher = ENGINE_get_cipher(e, NID_aes_128_cbc);
    ctx = EVP_CIPHER_CTX_new();
    if (cipher != NULL && ctx != NULL)
        ret = EVP_EncryptInit_ex(ctx, cipher, e, NULL, NULL);
    TEST_true(ret);
    EVP_CIPHER_CTX_free(ctx);
    ENGINE_finish(e);
    return ret;
}

int global_init(void)
{
    ENGINE_load_builtin_engines();
# ifndef OPENSSL_NO_STATIC_ENGINE
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL);
# endif
    return 1;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ENGINE
    if ((e = ENGINE_by_id("afalg")) == NULL) {
        /* Probably a platform env issue, not a test failure. */
        TEST_info("Can't load AFALG engine");
    } else {
        ADD_ALL_TESTS(test_afalg_aes_cbc, 3);
        ADD_TEST(test_pr16743);
    }
#endif

    return 1;
}

#ifndef OPENSSL_NO_ENGINE
void cleanup_tests(void)
{
    ENGINE_free(e);
}
#endif
