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


typedef struct smtc_crng_test_global_st {
    CRYPTO_RWLOCK *lock;
    EVP_MD_CTX *md_ctx;
    int sample;
    size_t cnt;
} SMTC_CRNG_TEST_GLOBAL;

/* Modified based on hash_df() in drbg_hash.c */
static int sm3_df(EVP_MD_CTX *ctx, unsigned char *out, size_t outlen,
                  const unsigned char *in, size_t inlen)
{
    unsigned char vtmp[EVP_MAX_MD_SIZE];
    /* tmp = counter || num_bits_returned */
    unsigned char tmp[1 + 4];
    int tmp_sz = 0;
    size_t blocklen = EVP_MD_get_size(EVP_sm3());
    size_t num_bits_returned = outlen * 8;

    /* counter = 1 (tmp[0] is the 8 bit counter) */
    tmp[tmp_sz++] = 1;
    /* tmp[1..4] is the fixed 32 bit no_of_bits_to_return */
    tmp[tmp_sz++] = (unsigned char)((num_bits_returned >> 24) & 0xff);
    tmp[tmp_sz++] = (unsigned char)((num_bits_returned >> 16) & 0xff);
    tmp[tmp_sz++] = (unsigned char)((num_bits_returned >> 8) & 0xff);
    tmp[tmp_sz++] = (unsigned char)(num_bits_returned & 0xff);

    for (;;) {
        /*
         * out = out || Hash(tmp || in)
         *      (where tmp = counter || num_bits_returned)
         */
        if (!(EVP_DigestInit_ex(ctx, EVP_sm3(), NULL)
                && EVP_DigestUpdate(ctx, tmp, tmp_sz)
                && EVP_DigestUpdate(ctx, in, inlen)))
            return 0;

        if (outlen < blocklen) {
            if (!EVP_DigestFinal(ctx, vtmp, NULL))
                return 0;
            memcpy(out, vtmp, outlen);
            OPENSSL_cleanse(vtmp, blocklen);
            break;
        } else if(!EVP_DigestFinal(ctx, out, NULL)) {
            return 0;
        }

        outlen -= blocklen;
        if (outlen == 0)
            break;

        tmp[0]++;
        out += blocklen;
    }

    return 1;
}

static void rand_smtc_crng_ossl_ctx_free(void *vcrngt_glob)
{
    SMTC_CRNG_TEST_GLOBAL *smtc_glob = vcrngt_glob;

    CRYPTO_THREAD_lock_free(smtc_glob->lock);
    EVP_MD_CTX_free(smtc_glob->md_ctx);
    OPENSSL_free(smtc_glob);
}

static void *rand_smtc_crng_ossl_ctx_new(OSSL_LIB_CTX *ctx)
{
    SMTC_CRNG_TEST_GLOBAL *smtc_glob = OPENSSL_zalloc(sizeof(*smtc_glob));

    if (smtc_glob == NULL)
        return NULL;

    if ((smtc_glob->md_ctx = EVP_MD_CTX_new()) == NULL) {
        OPENSSL_free(smtc_glob);
        return NULL;
    }

    if ((smtc_glob->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        OPENSSL_free(smtc_glob);
        return NULL;
    }

    smtc_glob->sample = -1;
    smtc_glob->cnt = 0;

    return smtc_glob;
}

static const OSSL_LIB_CTX_METHOD rand_smtc_ossl_ctx_method = {
    OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY,
    rand_smtc_crng_ossl_ctx_new,
    rand_smtc_crng_ossl_ctx_free,
};

/* 1 + ceil(20/H) */
#define REPEAT_COUNT_TEST_THRESHOLD 4
/*
 * GM/T 0105-2021 Appendix D.2, Repeat Count Test
 */
static int smtc_rng_repeat_count_test(SMTC_CRNG_TEST_GLOBAL *crngt,
                                      const unsigned char *entropy, size_t len)
{
    size_t i;

    if (entropy == NULL || len == 0)
        return 0;

    for (i = 0; i < len; i++) {
        if (entropy[i] == crngt->sample) {
            crngt->cnt++;
            if (crngt->cnt >= REPEAT_COUNT_TEST_THRESHOLD)
                return 0;
        } else {
            crngt->sample = entropy[i];
            crngt->cnt = 1;
        }
    }

    return 1;
}

size_t ossl_smtc_get_entropy(PROV_DRBG *drbg, unsigned char **pout, int entropy,
                             size_t min_len, size_t max_len,
                             int prediction_resistance)
{
    unsigned char buf[CRNGT_BUFSIZ];
    int crng_test_pass = 1;
    OSSL_CALLBACK *stcb = NULL;
    void *stcbarg = NULL;
    unsigned char *ent, *entp, *entbuf;
    unsigned char *p = NULL;
    OSSL_SELF_TEST *st = NULL;
    size_t bytes_needed;
    size_t r = 0, s, t, n;

    OSSL_LIB_CTX *libctx = ossl_prov_ctx_get0_libctx(drbg->provctx);
    SMTC_CRNG_TEST_GLOBAL *crngt_glob = ossl_lib_ctx_get_data(
        libctx, OSSL_LIB_CTX_RAND_SMTC_CRNGT_INDEX, &rand_smtc_ossl_ctx_method);

    if (crngt_glob == NULL)
        return 0;

    if (!CRYPTO_THREAD_write_lock(crngt_glob->lock))
        return 0;

    /*
     * Calculate how many bytes of seed material we require, rounded up
     * to the nearest byte.
     */
    bytes_needed = (entropy + 7) / 8;
    if (bytes_needed < min_len)
        bytes_needed = min_len;
    if (bytes_needed > max_len)
        goto unlock_return;

    entp = ent = OPENSSL_secure_malloc(bytes_needed);
    if (ent == NULL)
        goto unlock_return;

    OSSL_SELF_TEST_get_callback(libctx, &stcb, &stcbarg);
    if (stcb != NULL) {
        st = OSSL_SELF_TEST_new(stcb, stcbarg);
        if (st == NULL)
            goto err;
        OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_CRNG,
                               OSSL_SELF_TEST_DESC_RNG);
    }

    for (t = bytes_needed; t > 0;) {
        /* Care needs to be taken to avoid overrunning the buffer */
        s = t >= CRNGT_BUFSIZ ? CRNGT_BUFSIZ : t;
        entbuf = t >= CRNGT_BUFSIZ ? entp : buf;

        n = ossl_prov_get_entropy(drbg->provctx, &p, 0, CRNGT_BUFSIZ,
                                  CRNGT_BUFSIZ);
        if (n == CRNGT_BUFSIZ) {
            if (OSSL_SELF_TEST_oncorrupt_byte(st, p))
                memset(p, 0, n);

            if (!smtc_rng_repeat_count_test(crngt_glob, p, n)) {
                ossl_set_error_state(OSSL_SELF_TEST_TYPE_CRNG);
                crng_test_pass = 0;
                goto err;
            }

            if (!sm3_df(crngt_glob->md_ctx, entbuf, CRNGT_BUFSIZ, p,
                        CRNGT_BUFSIZ))
                goto err;

            ossl_prov_cleanup_entropy(drbg->provctx, p, n);
        }

        if (n != 0) {
            ossl_prov_cleanup_entropy(drbg->provctx, p, n);
            p = NULL;
            goto err;
        }

        if (t < CRNGT_BUFSIZ)
            memcpy(entp, buf, t);

        entp += s;
        t -= s;
    }
    r = bytes_needed;
    *pout = ent;
    ent = NULL;

 err:
    OSSL_SELF_TEST_onend(st, crng_test_pass);
    OSSL_SELF_TEST_free(st);
    OPENSSL_secure_clear_free(ent, bytes_needed);

 unlock_return:
    CRYPTO_THREAD_unlock(crngt_glob->lock);
    return r;
}
