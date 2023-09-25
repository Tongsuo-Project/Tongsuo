/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Implementation of the GM/T 0105-2021 Appendix D Continuous Health Test.
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/self_test.h>
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/cryptlib.h"
#include "crypto/rand_pool.h"
#include "drbg_local.h"
#include "prov/seeding.h"
#include "crypto/evp.h"

#define REPEAT_COUNT_TEST_THRESHOLD 26

typedef struct smtc_crng_test_global_st {
    CRYPTO_RWLOCK *lock;
    unsigned char last_bit;
    size_t cnt;
} SMTC_CRNG_TEST_GLOBAL;

static int get_bit(const unsigned char *buf, int m)
{
    if (m < 0)
        return 0;

    return (buf[m / 8] << (m % 8) >> 7) & 1;
}

static void rand_smtc_crng_ossl_ctx_free(void *vcrngt_glob)
{
    SMTC_CRNG_TEST_GLOBAL *smtc_glob = vcrngt_glob;

    CRYPTO_THREAD_lock_free(smtc_glob->lock);
    OPENSSL_free(smtc_glob);
}

static void *rand_smtc_crng_ossl_ctx_new(OSSL_LIB_CTX *ctx)
{
    SMTC_CRNG_TEST_GLOBAL *smtc_glob = OPENSSL_zalloc(sizeof(*smtc_glob));

    if (smtc_glob == NULL)
        return NULL;

    if ((smtc_glob->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        OPENSSL_free(smtc_glob);
        return NULL;
    }

    return smtc_glob;
}

static const OSSL_LIB_CTX_METHOD rand_smtc_ossl_ctx_method = {
    OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY,
    rand_smtc_crng_ossl_ctx_new,
    rand_smtc_crng_ossl_ctx_free,
};

/*
 * GM/T 0105-2021 Appendix D.2, Repeat Count Test
 */
static int smtc_rng_repeat_count_test(SMTC_CRNG_TEST_GLOBAL *crngt,
                                     unsigned char *pout, size_t len,
                                     OSSL_SELF_TEST *st)
{
    size_t i = 0;

    if (len <= 0)
        return 0;

    if (crngt->cnt == 0) {
        crngt->last_bit = get_bit(pout, 0);
        crngt->cnt = i = 1;
    }

    for (; i < len * 8; i++) {
        unsigned char bit = get_bit(pout, i);
        if (bit == crngt->last_bit) {
            crngt->cnt++;
            if (crngt->cnt >= REPEAT_COUNT_TEST_THRESHOLD) {
                crngt->cnt = 0;
                OSSL_SELF_TEST_oncorrupt_byte(st, &pout[i / 8]);
                return 0;
            }
        } else {
            crngt->last_bit = bit;
            crngt->cnt = 1;
        }
    }

    return 1;
}

size_t ossl_smtc_get_entropy(PROV_DRBG *drbg, unsigned char **pout, int entropy,
                             size_t min_len, size_t max_len,
                             int prediction_resistance)
{
    int crng_test_pass = 0;
    OSSL_CALLBACK *stcb = NULL;
    void *stcbarg = NULL;
    OSSL_SELF_TEST *st = NULL;
    size_t ret
        = ossl_prov_get_entropy(drbg->provctx, pout, entropy, min_len, max_len);
    if (ret == 0)
        return 0;

    OSSL_LIB_CTX *libctx = ossl_prov_ctx_get0_libctx(drbg->provctx);
    SMTC_CRNG_TEST_GLOBAL *crngt_glob = ossl_lib_ctx_get_data(
        libctx, OSSL_LIB_CTX_RAND_SMTC_CRNGT_INDEX, &rand_smtc_ossl_ctx_method);

    if (crngt_glob == NULL)
        return 0;

    if (!CRYPTO_THREAD_write_lock(crngt_glob->lock))
        return 0;

    OSSL_SELF_TEST_get_callback(libctx, &stcb, &stcbarg);
    if (stcb != NULL) {
        st = OSSL_SELF_TEST_new(stcb, stcbarg);
        if (st == NULL)
            goto err;
        OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_CRNG,
                               OSSL_SELF_TEST_DESC_RNG);
    }

    if (!smtc_rng_repeat_count_test(crngt_glob, *pout, ret, st)) {
        ret = 0;
        goto err;
    }

    crng_test_pass = 1;

err:
    OSSL_SELF_TEST_onend(st, crng_test_pass);
    OSSL_SELF_TEST_free(st);
    CRYPTO_THREAD_unlock(crngt_glob->lock);
    return ret;
}
