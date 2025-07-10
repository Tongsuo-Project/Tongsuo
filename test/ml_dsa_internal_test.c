/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Internal tests for the ML-DSA module.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <crypto/evp.h>
#include "testutil.h"

#include "crypto/ml_dsa.h"

#ifndef OPENSSL_NO_ML_DSA

#define MLEN 59
#define CTXLEN 100
#define NTESTS 1000

#define RUN_ML_DSA_TESTS(mode) \
    do { \
        for (i = 0; i < NTESTS; ++i) { \
            RAND_bytes(m, MLEN); \
            pqcrystals_ml_dsa_##mode##_keypair(pk, sk, NULL); \
            pqcrystals_ml_dsa_##mode(sm, &smlen, m, MLEN, ctx, MLEN, sk); \
            ret = pqcrystals_ml_dsa_##mode##_open(m2, &mlen, sm, smlen, ctx, MLEN, pk); \
            if (!TEST_int_eq(ret, 0)) { \
                TEST_error("[-] Verification failed\n"); \
                goto end; \
            } \
            if (!TEST_int_eq(mlen, MLEN)) { \
                TEST_error("[-] Message lengths don't match\n"); \
                goto end; \
            } \
            if (!TEST_mem_eq(m, mlen, m2, mlen)) { \
                TEST_error("[-] Messages don't match\n"); \
                goto end; \
            } \
            RAND_bytes((uint8_t *)&j, sizeof(j)); \
            do { \
                RAND_bytes(m2, 1); \
            } while (!m2[0]); \
            sm[j % ML_DSA_SIGBYTES] += m2[0]; \
            ret = pqcrystals_ml_dsa_##mode##_open(m2, &mlen, sm, smlen, ctx, MLEN, pk); \
            if (!TEST_int_eq(ret, -1)) { \
                TEST_error("[-] Trivial forgeries possible\n"); \
                goto end; \
            } \
        } \
    } while (0)


static int test_ml_dsa_internal(void)
{
    static unsigned int i, j;
    static int ret = 0;
    static size_t mlen, smlen;
    static uint8_t m[MLEN] = {0};
    static uint8_t sm[MLEN + ML_DSA_SIGBYTES] = {0};
    static uint8_t m2[MLEN + ML_DSA_SIGBYTES] = {0};
    static uint8_t pk[ML_DSA_PUBLICKEYBYTES] = {0};
    static uint8_t sk[ML_DSA_SECRETKEYBYTES] = {0};
    static uint8_t ctx[MLEN];

    RAND_bytes(ctx, MLEN);
    RUN_ML_DSA_TESTS(65);

    return 1;

end:
    return 0;
}

static EVP_PKEY *do_gen_key(uint8_t *seed, size_t seed_len) {
    static int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2], *p = params;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                 (char *)seed, seed_len);
    *p = OSSL_PARAM_construct_end();
    
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (!TEST_ptr(ctx)) {
        goto end;
    }
    
    ret = EVP_PKEY_keygen_init(ctx);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    ret = EVP_PKEY_CTX_set_params(ctx, params);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }

    ret = EVP_PKEY_generate(ctx, &key);
    if (!TEST_int_eq(ret, 1)) {
        goto end;
    }
    return key;

end:
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static int test_ml_dsa_genkey_diff(void) {
    static uint8_t pk[ML_DSA_PUBLICKEYBYTES] = {0};
    static uint8_t sk[ML_DSA_SECRETKEYBYTES] = {0};
    static uint8_t pk2[ML_DSA_PUBLICKEYBYTES] = {0};
    static uint8_t sk2[ML_DSA_SECRETKEYBYTES] = {0};
    size_t sk_len = 0, pk_len = 0, sk2_len = 0, pk2_len = 0;
    uint8_t seed[ML_DSA_SEEDBYTES] = {0};
    EVP_PKEY *k1 = NULL, *k2 = NULL;
    int bits = 0, sig_len = 0;

    k1 = do_gen_key(seed, 0);
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
        || !TEST_int_ge(sig_len, 3309)) {
        goto end;
    }

    memset(seed, 1, ML_DSA_SEEDBYTES);
    k2 = do_gen_key(seed, ML_DSA_SEEDBYTES);
    if (!TEST_ptr(k1)) {
        goto end;
    }

    if (!TEST_true(EVP_PKEY_get_octet_string_param(k2, OSSL_PKEY_PARAM_PRIV_KEY,
                                                        sk2, sizeof(sk2), &sk2_len))
        || !TEST_true(EVP_PKEY_get_octet_string_param(k2, OSSL_PKEY_PARAM_PUB_KEY,
                                                        pk2, sizeof(pk2), &pk2_len))
        || !TEST_int_eq(sk2_len, ML_DSA_SECRETKEYBYTES)
        || !TEST_int_eq(pk2_len, ML_DSA_PUBLICKEYBYTES))
        goto end;

    if (!TEST_mem_ne(pk, pk_len, pk2, pk2_len)) {
        goto end;
    }
    if (!TEST_mem_ne(sk, sk_len, sk2, sk2_len)) {
        goto end;
    }

    return 1;
end:
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    return 0;
}

static int test_ml_dsa_signverify(void) {
    static uint8_t m[MLEN] = {0};
    static uint8_t sig[ML_DSA_SIGBYTES] = {0};
    size_t sig_len = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    static uint8_t ctx[CTXLEN];
    uint8_t seed[ML_DSA_SEEDBYTES];
    OSSL_PARAM params[3];
    int deterministic = 0, i;

    for (i = 0; i < NTESTS; i++) {
        RAND_bytes(seed, ML_DSA_SEEDBYTES);
        RAND_bytes(ctx, CTXLEN);
        RAND_bytes(m, MLEN);

        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65", seed, sizeof(seed));
        if (!TEST_ptr(pkey))
            goto err;

        // sign
        sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!TEST_ptr(sctx))
            goto err;

        if (!TEST_int_eq(EVP_PKEY_sign_init(sctx), 1))
            goto err;
        
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, sizeof(ctx));
        params[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
        params[2] = OSSL_PARAM_construct_end();
        if (!TEST_int_eq(EVP_PKEY_CTX_set_params(sctx, params), 1))
            goto err;

        if (!TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig_len, m, sizeof(m)), 1) 
                || !TEST_int_ge(sig_len, ML_DSA_SIGBYTES))
            goto err;

        if (!TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len, m, sizeof(m)), 1))
            goto err;

        // verify
        vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!TEST_ptr(vctx))
            goto err;

        if (!TEST_int_eq(EVP_PKEY_verify_init(vctx), 1))
            goto err;
        
        if (!TEST_int_eq(EVP_PKEY_CTX_set_params(vctx, params), 1))
            goto err;

        if (!TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len, m, sizeof(m)), 1))
            goto err;
        
        // negative tests
        sig[0] = sig[0] ^ 0xff;
        if (!TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len, m, sizeof(m)), 0))
            goto err;

        sig[0] = sig[0] ^ 0xff;
        m[1] = m[1] ^ 0xff;
        if (!TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len, m, sizeof(m)), 0))
            goto err;
    }

    return 1;
err:
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_free(pkey);

    return 0;
}

#endif


int setup_tests(void)
{
#ifndef OPENSSL_NO_ML_DSA
    ADD_TEST(test_ml_dsa_internal);
    ADD_TEST(test_ml_dsa_genkey_diff);
    ADD_TEST(test_ml_dsa_signverify);
#endif
    return 1;
}
