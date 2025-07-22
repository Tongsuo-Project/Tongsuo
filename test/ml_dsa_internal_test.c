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


#include <openssl/pem.h>
#include <crypto/evp.h>
#include "testutil.h"
#include "internal/nelem.h"

#include "crypto/ml_dsa.h"
#include "ml_dsa.inc"

#ifndef OPENSSL_NO_ML_DSA

#define MLEN 59
#define CTXLEN 100
#define NTESTS 1000
#define ALG_NAME "ML-DSA-65"

#define RUN_ML_DSA_TESTS(mode) \
    do { \
        for (i = 0; i < NTESTS; ++i) { \
            RAND_bytes(m, MLEN); \
            pqcrystals_ml_dsa_##mode##_keypair(pk, sk, seed, 1); \
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


static int test_ml_dsa_internal(void) {
    static unsigned int i, j;
    static int ret = 0;
    static size_t mlen, smlen;
    static uint8_t m[MLEN] = {0};
    static uint8_t sm[MLEN + ML_DSA_SIGBYTES] = {0};
    static uint8_t m2[MLEN + ML_DSA_SIGBYTES] = {0};
    static uint8_t pk[ML_DSA_PUBLICKEYBYTES] = {0};
    static uint8_t sk[ML_DSA_SECRETKEYBYTES] = {0};
    static uint8_t ctx[MLEN];
    static uint8_t seed[ML_DSA_SEEDBYTES];

    RAND_bytes(ctx, MLEN);
    RUN_ML_DSA_TESTS(65);

    return 1;

end:
    return 0;
}

static EVP_PKEY *do_gen_key(const uint8_t *seed, size_t seed_len) {
    static int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2], *p = params;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                 (char *)seed, seed_len);
    *p = OSSL_PARAM_construct_end();
    
    ctx = EVP_PKEY_CTX_new_from_name(NULL, ALG_NAME, NULL);
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
    EVP_PKEY_CTX_free(ctx);
    return key;

end:
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static int test_ml_dsa_keygen_KAT(int tst_id) {
    int ret = 0;
    const ML_DSA_KEYGEN_TEST_DATA *tst = &ml_dsa_keygen_testdata[tst_id];
    EVP_PKEY *pkey = NULL;
    uint8_t priv[5 * 1024], pub[3 * 1024];
    size_t priv_len, pub_len;

    if (!TEST_ptr(pkey = do_gen_key(tst->seed, tst->seed_len))
            || !TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                                          priv, sizeof(priv), &priv_len))
            || !TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                          pub, sizeof(pub), &pub_len))
            || !TEST_mem_eq(pub, pub_len, tst->pub, tst->pub_len)
            || !TEST_mem_eq(priv, priv_len, tst->priv, tst->priv_len))
        goto err;
    ret = 1;
err:
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_ml_dsa_genkey_diff(void) {
    int ret = 0;
    static uint8_t pk[ML_DSA_PUBLICKEYBYTES] = {0};
    static uint8_t sk[ML_DSA_SECRETKEYBYTES] = {0};
    static uint8_t pk2[ML_DSA_PUBLICKEYBYTES] = {0};
    static uint8_t sk2[ML_DSA_SECRETKEYBYTES] = {0};
    size_t sk_len = 0, pk_len = 0, sk2_len = 0, pk2_len = 0;
    uint8_t seed[ML_DSA_SEEDBYTES] = {0};
    EVP_PKEY *k1 = NULL, *k2 = NULL;
    int bits = 0, sig_len = 0;

    k1 = EVP_PKEY_Q_keygen(NULL, NULL, ALG_NAME);
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
    k2 = EVP_PKEY_Q_keygen(NULL, NULL, ALG_NAME);
    if (!TEST_ptr(k2)) {
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

    ret = 1;
end:
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    return ret;
}

static int test_ml_dsa_siggen_KAT(int tst_id) {
    int ret = 0, selection = 0;
    const ML_DSA_SIG_GEN_TEST_DATA *td = &ml_dsa_siggen_testdata[tst_id];
    EVP_PKEY_CTX *kctx = NULL, *sctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    uint8_t *psig = NULL;
    size_t psig_len = 0, sig_len2 = 0;
    int deterministic = 1;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                (uint8_t *)td->priv, td->priv_len);
    params[1] = OSSL_PARAM_construct_end();
    selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

    if (!TEST_ptr(kctx = EVP_PKEY_CTX_new_from_name(NULL, ALG_NAME, NULL))
            || !TEST_int_eq(EVP_PKEY_fromdata_init(kctx), 1)
            || !TEST_int_eq(EVP_PKEY_fromdata(kctx, &pkey, selection,
                                              params), 1))
        goto err;

    params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)td->context, td->context_len);
    params[2] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL))
            || !TEST_int_eq(EVP_PKEY_sign_init(sctx), 1)
            || !TEST_int_eq(EVP_PKEY_CTX_set_params(sctx, params), 1)
            || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &psig_len,
                                          td->msg, td->msg_len), 1)
            || !TEST_true(EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_MAX_SIZE,
                                                    &sig_len2))
            || !TEST_int_eq(sig_len2, psig_len)
            || !TEST_ptr(psig = OPENSSL_zalloc(psig_len))
            || !TEST_int_eq(EVP_PKEY_sign(sctx, psig, &psig_len,
                                          td->msg, td->msg_len), 1)
            || !TEST_mem_eq(psig, psig_len, td->sig, td->sig_len))
        goto err;
    ret = 1;

err:
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(sctx);
    OPENSSL_free(psig);
    return ret;
}

static int test_ml_dsa_signverify(void) {
    int ret = 0;
    static uint8_t m[MLEN] = {0};
    static uint8_t sig[ML_DSA_SIGBYTES] = {0};
    size_t sig_len = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    static uint8_t ctx[CTXLEN];
    OSSL_PARAM params[3];
    int deterministic = 0, i;

    for (i = 0; i < NTESTS; i++) {
        RAND_bytes(ctx, CTXLEN);
        RAND_bytes(m, MLEN);

        pkey = EVP_PKEY_Q_keygen(NULL, NULL, ALG_NAME);
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

    ret = 1;
err:
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_free(pkey);

    return ret;
}

static int test_ml_dsa_export(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL, *pkey2_from_priv = NULL, *pkey3_from_pub = NULL;
    BIO *bio_priv_in = NULL, *bio_priv_out = NULL;
    BIO *bio_pub_in = NULL, *bio_pub_out = NULL;
    
    // 解除公钥相关变量的注释
    size_t pub_len1 = 0, pub_len2 = 0;
    uint8_t pub1[ML_DSA_PUBLICKEYBYTES] = {0};
    uint8_t pub2[ML_DSA_PUBLICKEYBYTES] = {0};

    size_t priv_len1 = 0, priv_len2 = 0;
    uint8_t priv1[ML_DSA_SECRETKEYBYTES] = {0};
    uint8_t priv2[ML_DSA_SECRETKEYBYTES] = {0};

    #define PRIV_PEM_FILE_NAME "test_mldsa_private_key.pem"
    #define PUB_PEM_FILE_NAME "test_mldsa_public_key.pem"

    /* --- 1. 生成原始密钥对 --- */
    pkey = EVP_PKEY_Q_keygen(NULL, NULL, ALG_NAME);
    if (!TEST_ptr(pkey))
        goto err;

    /* --- 2. 测试私钥的导出和导入 --- */
    TEST_info("Testing Private Key Export/Import...");

    bio_priv_out = BIO_new_file(PRIV_PEM_FILE_NAME, "w+");
    if (!TEST_ptr(bio_priv_out))
        goto err;

    // 使用 PKCS8 格式导出私钥
    if (!TEST_int_eq(PEM_write_bio_PKCS8PrivateKey(bio_priv_out, pkey, NULL, NULL, 0, NULL, NULL), 1))
        goto err;
    BIO_free_all(bio_priv_out);
    bio_priv_out = NULL; // 避免在 err 标签中重复释放

    bio_priv_in = BIO_new_file(PRIV_PEM_FILE_NAME, "r");
    if (!TEST_ptr(bio_priv_in))
        goto err;

    pkey2_from_priv = PEM_read_bio_PrivateKey(bio_priv_in, NULL, NULL, NULL);
    if (!TEST_ptr(pkey2_from_priv)) {
        TEST_error("Failed to import private key from PEM.");
        goto err;
    }
    
    // 比较原始密钥和从 PEM 文件导入的密钥的私钥部分
    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, priv1, sizeof(priv1), &priv_len1)) ||
        !TEST_true(EVP_PKEY_get_octet_string_param(pkey2_from_priv, OSSL_PKEY_PARAM_PRIV_KEY, priv2, sizeof(priv2), &priv_len2)) ||
        !TEST_mem_eq(priv1, priv_len1, priv2, priv_len2)) {
        TEST_error("Private keys do not match after PEM import.");
        goto err;
    }
    TEST_info("Private key test PASSED.");


    /* --- 3. 继续测试公钥的导出和导入 --- */
    TEST_info("Testing Public Key Export/Import...");
    
    bio_pub_out = BIO_new_file(PUB_PEM_FILE_NAME, "w+");
    if (!TEST_ptr(bio_pub_out))
        goto err;

    // 使用标准格式导出公钥
    if (!TEST_int_eq(PEM_write_bio_PUBKEY(bio_pub_out, pkey), 1))
        goto err;
    BIO_free_all(bio_pub_out);
    bio_pub_out = NULL; // 避免在 err 标签中重复释放

    bio_pub_in = BIO_new_file(PUB_PEM_FILE_NAME, "r");
    if (!TEST_ptr(bio_pub_in))
        goto err;
    
    // 从 PEM 文件中读取公钥
    pkey3_from_pub = PEM_read_bio_PUBKEY(bio_pub_in, NULL, NULL, NULL);
    if (!TEST_ptr(pkey3_from_pub)) {
        TEST_error("Failed to import public key from PEM.");
        goto err;
    }

    // 比较原始密钥和从公钥 PEM 文件导入的密钥的公钥部分
    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub1, sizeof(pub1), &pub_len1)) ||
        !TEST_true(EVP_PKEY_get_octet_string_param(pkey3_from_pub, OSSL_PKEY_PARAM_PUB_KEY, pub2, sizeof(pub2), &pub_len2)) ||
        !TEST_mem_eq(pub1, pub_len1, pub2, pub_len2)) {
        TEST_error("Public keys do not match after PEM import.");
        goto err;
    }
    TEST_info("Public key test PASSED.");

    // 最终成功
    ret = 1;

err:
    // 清理所有资源
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey2_from_priv);
    EVP_PKEY_free(pkey3_from_pub);
    BIO_free_all(bio_priv_in);
    BIO_free_all(bio_priv_out);
    BIO_free_all(bio_pub_in);
    BIO_free_all(bio_pub_out);
    // 清理测试文件
    remove(PRIV_PEM_FILE_NAME);
    remove(PUB_PEM_FILE_NAME);
    return ret;
}


#endif


int setup_tests(void)
{
#ifndef OPENSSL_NO_ML_DSA
    ADD_TEST(test_ml_dsa_internal);
    ADD_ALL_TESTS(test_ml_dsa_keygen_KAT, OSSL_NELEM(ml_dsa_keygen_testdata));
    ADD_TEST(test_ml_dsa_genkey_diff);
    ADD_ALL_TESTS(test_ml_dsa_siggen_KAT, OSSL_NELEM(ml_dsa_siggen_testdata));
    ADD_TEST(test_ml_dsa_signverify);
    ADD_TEST(test_ml_dsa_export);

#endif
    return 1;
}
