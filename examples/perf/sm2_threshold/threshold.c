/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/* Performance test for SM2-threshold sign(TPS), verify(TPS), keygen(TPS) */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include <openssl/sm2_threshold.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

static long long get_time();

/* Iteration number, could be adjusted as required */
#define ITR_NUM 1000

/* Time difference on each index */
struct perf_index {
    int sm2_threshold_sign;
    int sm2_threshold_verify;
    int sm2_threshold_keygen;
};

/* Final result TPS */
struct perf_result {
    int sm2_threshold_sign_avg;
    int sm2_threshold_verify_avg;
    int sm2_threshold_keygen_avg;
};

static long long get_time()
{
    /* Use gettimeofday() to adequate for our case */
    struct timeval tp;

    if (gettimeofday(&tp, NULL) != 0)
        return 0;
    else
        return (long long)(tp.tv_sec * 1000 * 1000 + tp.tv_usec);
}

/* These values are from GM/T 0003.2-2012 standard */
static const char *userid = "ALICE123@YAHOO.COM";
static const char *message = "message digest";

int main(void)
{
    int ret = -1;
    struct perf_index *indices = NULL;
    struct perf_result result;
    int msg_len = strlen(message), i = 0;
    long long start = 0, end = 0;
    EVP_PKEY *key1 = NULL, *key2 = NULL, *pubkey1 = NULL, *pubkey2 = NULL;
    EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *sigbuf = NULL, *final_sig = NULL;
    EVP_PKEY *temp_key = NULL;
    size_t siglen, final_siglen;
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t dlen = 0;

    memset(&result, 0, sizeof(result));
    indices = malloc(sizeof(struct perf_index) * ITR_NUM);
    if (indices == NULL) {
        fprintf(stderr, "malloc error - indices\n");
        return -1;
    }
    memset(indices, 0, sizeof(struct perf_index) * ITR_NUM);

    for (; i < ITR_NUM; i++) {
        fprintf(stdout, "Iteration %d: ", i);

        /* SM2 threshold keygen */
        start = get_time();

        key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
        key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
        if (key1 == NULL || key2 == NULL)
            goto err;

        if ((pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1)) == NULL
            || (pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2)) == NULL)
            goto err;

        if ((complete_key1 = SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2)) == NULL
            || (complete_key2 = SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1)) == NULL)
            goto err;

        end = get_time();

        /* Generate 2 keypair per iteration, so the result need to multiple 2 */
        indices[i].sm2_threshold_keygen = 1000 * 1000 * 2/ (end - start);

        temp_key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
        if (temp_key == NULL)
            goto err;

        /* SM2 threshold sign */
        start = get_time();
        if (!SM2_THRESHOLD_sign1_oneshot(complete_key1, EVP_sm3(),
                                         (const uint8_t *)userid,
                                         strlen(userid),
                                         (const uint8_t *)message,
                                         msg_len, digest, &dlen)
                || !SM2_THRESHOLD_sign2(key2, temp_key, digest, dlen, &sigbuf,
                                        &siglen)
                || !SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen,
                                        &final_sig, &final_siglen))
            goto err;
        end = get_time();
        indices[i].sm2_threshold_sign = 1000 * 1000 / (end - start);

        start = get_time();

        if ((mctx = EVP_MD_CTX_new()) == NULL
            || (pctx = EVP_PKEY_CTX_new(complete_key1, NULL)) == NULL)
            goto err;

        EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

        if (!EVP_PKEY_CTX_set1_id(pctx, userid, strlen(userid)))
            goto err;

        if (!EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, complete_key1)
            || !EVP_DigestVerify(mctx, final_sig, final_siglen,
                                 (const unsigned char *)message, msg_len))
            goto err;

        end = get_time();
        indices[i].sm2_threshold_verify = 1000 * 1000 / (end - start);

        EVP_PKEY_free(key1);
        key1 = NULL;
        EVP_PKEY_free(key2);
        key2 = NULL;
        EVP_PKEY_free(pubkey1);
        pubkey1 = NULL;
        EVP_PKEY_free(pubkey2);
        pubkey2 = NULL;
        EVP_PKEY_free(complete_key1);
        complete_key1 = NULL;
        EVP_PKEY_free(complete_key2);
        complete_key2 = NULL;
        EVP_PKEY_free(temp_key);
        temp_key = NULL;
        OPENSSL_free(sigbuf);
        sigbuf = NULL;
        OPENSSL_free(final_sig);
        final_sig = NULL;
        EVP_MD_CTX_free(mctx);
#if 1
        fprintf(stdout, "sm2-threshold-sign: %d, "
                        "sm2-threshold-verify: %d, "
                        "sm2-threshold-keygen: %d\n",
                        indices[i].sm2_threshold_sign,
                        indices[i].sm2_threshold_verify,
                        indices[i].sm2_threshold_keygen);
#endif
    }

    /* calculate the final average result */
    for (i = 0; i < ITR_NUM; i++) {
        result.sm2_threshold_sign_avg += indices[i].sm2_threshold_sign;
        result.sm2_threshold_verify_avg += indices[i].sm2_threshold_verify;
        result.sm2_threshold_keygen_avg += indices[i].sm2_threshold_keygen;
    }

    result.sm2_threshold_sign_avg /= ITR_NUM;
    result.sm2_threshold_verify_avg /= ITR_NUM;
    result.sm2_threshold_keygen_avg /= ITR_NUM;

    fprintf(stdout, "sm2-threshold-sign: %d/s\n"
            "sm2-threshold-verify: %d/s\n"
            "sm2-threshold-keygen: %d/s\n",
            result.sm2_threshold_sign_avg, result.sm2_threshold_verify_avg,
            result.sm2_threshold_keygen_avg);

    ret = 0;
err:
    if (ret != 0)
        fprintf(stderr, "Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
    OPENSSL_free(indices);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    EVP_PKEY_free(complete_key1);
    EVP_PKEY_free(complete_key2);
    EVP_PKEY_free(temp_key);

    return ret;
}
