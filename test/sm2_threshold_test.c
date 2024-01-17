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

static int sm2_threshold_keygen_test(void)
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

static int sm2_threshold_sign_test(int id)
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

#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_SM2_THRESHOLD
    TEST_note("SM2 threshold is disabled.");
#else
    ADD_TEST(sm2_threshold_keygen_test);
    ADD_ALL_TESTS(sm2_threshold_sign_test, 2);
#endif
    return 1;
}
