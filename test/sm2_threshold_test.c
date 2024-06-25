/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "testutil.h"

#ifndef OPENSSL_NO_SM2_THRESHOLD

# include <openssl/sm2_threshold.h>

/* These values are from GM/T 0003.2-2012 standard */
static const char *userid = "ALICE123@YAHOO.COM";
static const char *message = "message digest";

static int test_sm2_threshold_keygen(void)
{
    int ret = 0;
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    EVP_PKEY *pubkey1 = NULL, *pubkey2 = NULL;
    EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL;

    if (!TEST_ptr(key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2"))
        || !TEST_ptr(key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")))
        goto err;

    if (!TEST_ptr(pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1))
        || !TEST_ptr(pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2)))
        goto err;

    if (!TEST_ptr(complete_key1 =
                        SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2))
        || !TEST_ptr(complete_key2 =
                        SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1)))
        goto err;

    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    EVP_PKEY_free(pubkey1);
    EVP_PKEY_free(pubkey2);
    EVP_PKEY_free(complete_key1);
    EVP_PKEY_free(complete_key2);

    return ret;
}

static int test_sm2_threshold_sign(int id)
{
    int ret = 0;
    int msg_len = strlen(message);
    EVP_PKEY *key1 = NULL, *key2 = NULL, *pubkey1 = NULL, *pubkey2 = NULL;
    EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL, *temp_key = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *sigbuf = NULL, *final_sig = NULL;
    size_t siglen, final_siglen, dlen;
    unsigned char digest[EVP_MAX_MD_SIZE];

    if (!TEST_ptr(key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2"))
        || !TEST_ptr(key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")))
        goto err;

    if (!TEST_ptr(pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1))
        || !TEST_ptr(pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2)))
        goto err;

    if (!TEST_ptr(complete_key1 =
                        SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2))
        || !TEST_ptr(complete_key2 =
                        SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1)))
        goto err;

    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    if (!TEST_ptr(temp_key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")))
        goto err;

    /* Test SM2 threshold sign with id */
    if (id == 0) {
        if (!TEST_true(SM2_THRESHOLD_sign1_oneshot(complete_key1, EVP_sm3(),
                                                   (const uint8_t *)userid,
                                                   strlen(userid),
                                                   (const uint8_t *)message,
                                                   msg_len,
                                                   digest, &dlen))
            || !TEST_true(SM2_THRESHOLD_sign2(key2, temp_key, digest, dlen,
                                              &sigbuf, &siglen))
            || !TEST_true(SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen,
                                              &final_sig, &final_siglen)))
            goto err;

        if (!TEST_ptr(mctx = EVP_MD_CTX_new())
            || !TEST_ptr(pctx = EVP_PKEY_CTX_new(complete_key1, NULL)))
            goto err;

        EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

        if (!TEST_true(EVP_PKEY_CTX_set1_id(pctx, userid, strlen(userid))))
            goto err;

        if (!TEST_true(EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL,
                                            complete_key1))
            || !TEST_true(EVP_DigestVerify(mctx, final_sig, final_siglen,
                                           (const unsigned char *)message,
                                           msg_len)))
            goto err;
    } else {
        if (!TEST_true(SM2_THRESHOLD_sign1_oneshot(complete_key1, EVP_sm3(),
                                                   NULL, 0,
                                                   (const uint8_t *)message,
                                                   msg_len, digest, &dlen))
            || !TEST_true(SM2_THRESHOLD_sign2(key2, temp_key, digest, dlen,
                                              &sigbuf, &siglen))
            || !TEST_true(SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen,
                                              &final_sig, &final_siglen)))
            goto err;

        if (!TEST_ptr(mctx = EVP_MD_CTX_new())
            || !TEST_true(EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL,
                                               complete_key1))
            || !TEST_true(EVP_DigestVerify(mctx, final_sig, final_siglen,
                                           (const unsigned char *)message,
                                           msg_len)))
            goto err;
    }

    ret = 1;
err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    EVP_PKEY_free(pubkey1);
    EVP_PKEY_free(pubkey2);
    EVP_PKEY_free(complete_key1);
    EVP_PKEY_free(complete_key2);
    EVP_PKEY_free(temp_key);
    EVP_MD_CTX_free(mctx);
    OPENSSL_free(sigbuf);

    return ret;
}

static int test_sm2_threshold_decrypt(void)
{
    int ret = 0;
    const char *msg = "hello sm2 threshold";
    int msg_len = strlen(msg);
    EVP_PKEY *key1 = NULL, *key2 = NULL, *pubkey1 = NULL, *pubkey2 = NULL;
    EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIGNUM *w = NULL;
    EC_POINT *T1 = NULL, *T2 = NULL;
    unsigned char *ct = NULL, *pt = NULL;
    size_t pt_len, outlen;

    if (!TEST_ptr(key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2"))
        || !TEST_ptr(key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")))
        goto err;

    if (!TEST_ptr(pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1))
        || !TEST_ptr(pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2)))
        goto err;

    if (!TEST_ptr(complete_key1 =
                        SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2))
        || !TEST_ptr(complete_key2 =
                        SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1)))
        goto err;

    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new(complete_key1, NULL)))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt_init(pctx) == 1))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt(pctx, NULL, &outlen,
                                   (const unsigned char *)msg, msg_len) == 1))
        goto err;

    if (!TEST_ptr(ct = OPENSSL_malloc(outlen)))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt(pctx, ct, &outlen,
                                   (const unsigned char *)msg, msg_len) == 1))
        goto err;

    if (!TEST_true(SM2_THRESHOLD_decrypt1(ct, outlen, &w, &T1)))
        goto err;

    if (!TEST_true(SM2_THRESHOLD_decrypt2(key2, T1, &T2)))
        goto err;

    if (!TEST_true(SM2_THRESHOLD_decrypt3(key1, ct, outlen, w, T2, &pt, &pt_len)))
        goto err;

    if (!TEST_int_eq(pt_len, msg_len))
        goto err;

    if (!TEST_strn_eq((const char *)pt, msg, msg_len))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    EVP_PKEY_free(pubkey1);
    EVP_PKEY_free(pubkey2);
    EVP_PKEY_free(complete_key1);
    EVP_PKEY_free(complete_key2);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(ct);
    BN_free(w);
    EC_POINT_free(T1);
    EC_POINT_free(T2);
    OPENSSL_free(pt);

    return ret;
}
#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_SM2_THRESHOLD
    TEST_note("SM2 threshold is disabled.");
#else
    ADD_TEST(test_sm2_threshold_keygen);
    ADD_ALL_TESTS(test_sm2_threshold_sign, 2);
    ADD_TEST(test_sm2_threshold_decrypt);
#endif
    return 1;
}
