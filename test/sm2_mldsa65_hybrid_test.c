/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <crypto/evp.h>
#include "testutil.h"
#include "internal/nelem.h"
#include "crypto/sm2_mldsa65_hybrid.h"

#ifndef OPENSSL_NO_SM2_MLDSA65_HYBRID

#define MLEN 590
#define CTXLEN 100
#define NTESTS 1000
#define ALG_NAME "SM2-MLDSA65-HYBRID"
static EVP_PKEY *do_gen_key(void) {
    static int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, ALG_NAME, NULL);
    if (!TEST_ptr(ctx)) {
        goto end;
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    ret = EVP_PKEY_generate(ctx, &key);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;

end:
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static int test_sm2_mldsa65_hybrid_genkey(void) {
    int ret = 0;
    static uint8_t pk[SM2_MLDSA65_HYBRID_PK_SIZE] = {0};
    static uint8_t sk[SM2_MLDSA65_HYBRID_SK_SIZE] = {0};
    static uint8_t pk2[SM2_MLDSA65_HYBRID_PK_SIZE] = {0};
    static uint8_t sk2[SM2_MLDSA65_HYBRID_SK_SIZE] = {0};
    size_t sk_len = 0, pk_len = 0, sk2_len = 0, pk2_len = 0;
    EVP_PKEY *k1 = NULL, *k2 = NULL;
    int bits = 0, sig_len = 0;

    k1 = do_gen_key();
    if (!TEST_ptr(k1)) {
        goto end;
    }

    if (!TEST_true(EVP_PKEY_get_octet_string_param(k1, OSSL_PKEY_PARAM_PRIV_KEY,
                                                        sk, sizeof(sk), &sk_len))
        || !TEST_true(EVP_PKEY_get_octet_string_param(k1, OSSL_PKEY_PARAM_PUB_KEY,
                                                        pk, sizeof(pk), &pk_len))
        || !TEST_true(EVP_PKEY_get_int_param(k1, OSSL_PKEY_PARAM_BITS, &bits))
        || !TEST_int_eq(bits, 1952 * 8)
        || !TEST_true(EVP_PKEY_get_int_param(k1, OSSL_PKEY_PARAM_MAX_SIZE, &sig_len))
        || !TEST_int_ge(sig_len, 3309 + 72)) {
        goto end;
    }

    k2 = EVP_PKEY_Q_keygen(NULL, NULL, ALG_NAME);
    if (!TEST_ptr(k2)) {
        goto end;
    }

    if (!TEST_true(EVP_PKEY_get_octet_string_param(k2, OSSL_PKEY_PARAM_PRIV_KEY,
                                                        sk2, sizeof(sk2), &sk2_len))
        || !TEST_true(EVP_PKEY_get_octet_string_param(k2, OSSL_PKEY_PARAM_PUB_KEY,
                                                        pk2, sizeof(pk2), &pk2_len))
        || !TEST_int_eq(sk2_len, SM2_MLDSA65_HYBRID_SK_SIZE)
        || !TEST_int_eq(pk2_len, SM2_MLDSA65_HYBRID_PK_SIZE))
        goto end;

    if (!TEST_mem_ne(pk, pk_len, pk2, pk2_len)) {
        goto end;
    }
    if (!TEST_mem_ne(sk, sk_len, sk2, sk2_len)) {
        goto end;
    }

    ret = 1;
end:
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    return ret;
}

static int test_sm2_mldsa65_hybrid_signverify(void) {
    int ret = 0;
    static uint8_t m[MLEN] = {0};
    static uint8_t sig[SM2_MLDSA65_HYBRID_SIG_SIZE] = {0};
    size_t sig_len = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    static uint8_t ctx[CTXLEN];
    OSSL_PARAM params[3], *p = params;
    int i;

    for (i = 0; i < NTESTS; i++) {
        pkey = NULL;
        pctx = NULL;
        mctx = NULL;
        p = params;

        RAND_bytes(ctx, CTXLEN);
        RAND_bytes(m, MLEN);

        if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(NULL, ALG_NAME, NULL))
                || !TEST_int_eq(EVP_PKEY_keygen_init(pctx), 1)
                || !TEST_int_eq(EVP_PKEY_generate(pctx, &pkey), 1)) {
            EVP_PKEY_CTX_free(pctx);
            return 0;
        }
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;

        // sign
        mctx = EVP_MD_CTX_new();
        if (!TEST_ptr(mctx))
            goto err;

        if (!TEST_int_eq(EVP_DigestSignInit(mctx, &pctx, EVP_sm3(), NULL, pkey), 1))
            goto err;

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, sizeof(ctx));
        *p = OSSL_PARAM_construct_end();
        if (!TEST_int_eq(EVP_PKEY_CTX_set_params(pctx, params), 1))
            goto err;

        if (!TEST_int_eq(EVP_DigestSign(mctx, NULL, &sig_len, m, sizeof(m)), 1)
                || !TEST_int_ge(sig_len, SM2_MLDSA65_HYBRID_SIG_SIZE))
            goto err;

        if (!TEST_int_eq(EVP_DigestSign(mctx, sig, &sig_len, m, sizeof(m)), 1))
            goto err;

        EVP_MD_CTX_free(mctx);
        mctx = NULL;
        // verify
        mctx = EVP_MD_CTX_new();
        if (!TEST_ptr(mctx))
            goto err;

        if (!TEST_int_eq(EVP_DigestVerifyInit(mctx, &pctx, EVP_sm3(), NULL, pkey), 1))
            goto err;

        if (!TEST_int_eq(EVP_PKEY_CTX_set_params(pctx, params), 1))
            goto err;

        if (!TEST_int_eq(EVP_DigestVerify(mctx, sig, sig_len, m, sizeof(m)), 1))
            goto err;

        // negative tests
        sig[0] = sig[0] ^ 0xff;
        if (!TEST_int_eq(EVP_DigestVerify(mctx, sig, sig_len, m, sizeof(m)), 0))
            goto err;

        sig[0] = sig[0] ^ 0xff;
        m[1] = m[1] ^ 0xff;
        if (!TEST_int_eq(EVP_DigestVerify(mctx, sig, sig_len, m, sizeof(m)), 0))
            goto err;

        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
    }

    return 1;
err:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    return ret;
}

static int test_sm2_mldsa65_hybrid_export(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL, *pkey2_from_priv = NULL, *pkey3_from_pub = NULL;
    BIO *bio_pub = NULL, *bio_priv = NULL;

    size_t pub_len1 = 0, pub_len2 = 0;
    uint8_t pub1[SM2_MLDSA65_HYBRID_PK_SIZE] = {0};
    uint8_t pub2[SM2_MLDSA65_HYBRID_PK_SIZE] = {0};

    size_t priv_len1 = 0, priv_len2 = 0;
    uint8_t priv1[SM2_MLDSA65_HYBRID_SK_SIZE] = {0};
    uint8_t priv2[SM2_MLDSA65_HYBRID_SK_SIZE] = {0};

    /* --- 1. 生成原始密钥对 --- */
    pkey = EVP_PKEY_Q_keygen(NULL, NULL, ALG_NAME);
    if (!TEST_ptr(pkey))
        goto err;

    /* --- 2. 测试私钥的导出和导入 --- */
    TEST_info("Testing Private Key Export/Import...");

    bio_priv = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bio_priv))
        goto err;

    if (!TEST_int_eq(PEM_write_bio_PKCS8PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL), 1))
        goto err;

    pkey2_from_priv = PEM_read_bio_PrivateKey(bio_priv, NULL, NULL, NULL);
    if (!TEST_ptr(pkey2_from_priv)) {
        TEST_error("Failed to import private key from PEM.");
        goto err;
    }

    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, priv1, sizeof(priv1), &priv_len1)) ||
        !TEST_true(EVP_PKEY_get_octet_string_param(pkey2_from_priv, OSSL_PKEY_PARAM_PRIV_KEY, priv2, sizeof(priv2), &priv_len2)) ||
        !TEST_mem_eq(priv1, priv_len1, priv2, priv_len2)) {
        TEST_error("Private keys do not match after PEM import.");
        goto err;
    }
    TEST_info("Private key test PASSED.");


    /* --- 3. 继续测试公钥的导出和导入 --- */
    TEST_info("Testing Public Key Export/Import...");

    bio_pub = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bio_pub))
        goto err;

    if (!TEST_int_eq(PEM_write_bio_PUBKEY(bio_pub, pkey), 1))
        goto err;

    pkey3_from_pub = PEM_read_bio_PUBKEY(bio_pub, NULL, NULL, NULL);
    if (!TEST_ptr(pkey3_from_pub)) {
        TEST_error("Failed to import public key from PEM.");
        goto err;
    }

    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub1, sizeof(pub1), &pub_len1)) ||
        !TEST_true(EVP_PKEY_get_octet_string_param(pkey3_from_pub, OSSL_PKEY_PARAM_PUB_KEY, pub2, sizeof(pub2), &pub_len2)) ||
        !TEST_mem_eq(pub1, pub_len1, pub2, pub_len2)) {
        TEST_error("Public keys do not match after PEM import.");
        goto err;
    }
    TEST_info("Public key test PASSED.");

    ret = 1;

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey2_from_priv);
    EVP_PKEY_free(pkey3_from_pub);
    BIO_free_all(bio_priv);
    BIO_free_all(bio_pub);
    return ret;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_SM2_MLDSA65_HYBRID
    ADD_TEST(test_sm2_mldsa65_hybrid_genkey);
    ADD_TEST(test_sm2_mldsa65_hybrid_signverify);
    ADD_TEST(test_sm2_mldsa65_hybrid_export);
#endif
    return 1;
}
