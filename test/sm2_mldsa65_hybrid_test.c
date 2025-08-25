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

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_SM2_MLDSA65_HYBRID
    ADD_TEST(test_sm2_mldsa65_hybrid_genkey);
#endif
    return 1;
}
