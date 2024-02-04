/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/sm3.h>
#include "internal/cryptlib.h"
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "crypto/evp.h"
#include "internal/e_os.h"
#include "internal/thread_once.h"
#include "prov/providercommon.h"
#include "prov/seeding.h"
#include "prov/bio.h"
#include "smtckey.h"
#include "self_test.h"
#include "self_test_rand.h"
#include "../implementations/rands/drbg_local.h"
#include "../../crypto/evp/evp_local.h"

/* The size of a temp buffer used to read in data */
#define INTEGRITY_BUF_SIZE (4096)
#define MAX_MD_SIZE 64
#define MAC_NAME    "HMAC"
#define DIGEST_NAME "SM3"

static CRYPTO_RWLOCK *self_test_lock = NULL;
static CRYPTO_RWLOCK *smtc_state_lock = NULL;
static int smtc_state = SMTC_STATE_INIT;
static unsigned char fixed_key[32] = { SMTC_KEY_ELEMENTS };

static CRYPTO_ONCE smtc_self_test_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_smtc_self_test_init)
{
    /*
     * These locks get freed in platform specific ways that may occur after we
     * do mem leak checking. If we don't know how to free it for a particular
     * platform then we just leak it deliberately.
     */
    self_test_lock = CRYPTO_THREAD_lock_new();
    smtc_state_lock = CRYPTO_THREAD_lock_new();
    return self_test_lock != NULL;
}

/*
 * Calculate the HMAC SM3 of data read using a BIO and read_cb, and verify
 * the result matches the expected value.
 * Return 1 if verified, or 0 if it fails.
 */
static int verify_integrity(OSSL_CORE_BIO *bio, OSSL_FUNC_BIO_read_ex_fn read_ex_cb,
                            unsigned char *expected, size_t expected_len,
                            OSSL_LIB_CTX *libctx, OSSL_SELF_TEST *ev,
                            const char *event_type)
{
    int ret = 0, status;
    unsigned char out[MAX_MD_SIZE];
    unsigned char buf[INTEGRITY_BUF_SIZE];
    size_t bytes_read = 0, out_len = 0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2], *p = params;

    OSSL_SELF_TEST_onbegin(ev, event_type, OSSL_SELF_TEST_DESC_INTEGRITY_HMAC);

    mac = EVP_MAC_fetch(libctx, MAC_NAME, NULL);
    if (mac == NULL)
        goto err;
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        goto err;

    *p++ = OSSL_PARAM_construct_utf8_string("digest", DIGEST_NAME, 0);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx, fixed_key, sizeof(fixed_key), params))
        goto err;

    while (1) {
        status = read_ex_cb(bio, buf, sizeof(buf), &bytes_read);
        if (status != 1)
            break;
        if (!EVP_MAC_update(ctx, buf, bytes_read))
            goto err;
    }
    if (!EVP_MAC_final(ctx, out, &out_len, sizeof(out)))
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(ev, out);
    if (expected_len != out_len
            || memcmp(expected, out, out_len) != 0)
        goto err;
    ret = 1;
err:
    OSSL_SELF_TEST_onend(ev, ret);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

#define PASSWD_BUF_SIZE 1024

static int verify_password(OSSL_LIB_CTX *libctx, unsigned char *password,
                           size_t pass_len, unsigned char *salt,
                           size_t salt_len)
{
    int ret = 0;
    char passphrase[PASSWD_BUF_SIZE];
    EVP_MD_CTX *mctx = NULL;
    unsigned char buf[EVP_MAX_MD_SIZE];

    if (password == NULL || pass_len != SM3_DIGEST_LENGTH || salt == NULL
        || salt_len != SM3_DIGEST_LENGTH)
        goto end;

    if (EVP_read_pw_string(passphrase, sizeof(passphrase), "Enter password: ",
        0) != 0)
        goto end;

    if ((mctx = EVP_MD_CTX_new()) == NULL
        || !EVP_DigestInit_ex(mctx, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(mctx, salt, salt_len)
        || !EVP_DigestUpdate(mctx, passphrase, strlen(passphrase))
        || !EVP_DigestFinal_ex(mctx, buf, NULL))
        goto end;

    if (memcmp(buf, password, pass_len))
        goto end;

    ret = 1;
end:
    EVP_MD_CTX_free(mctx);
    return ret;
}

int smtc_prov_get_state(void)
{
    int state;

    if (ossl_assert(CRYPTO_THREAD_read_lock(smtc_state_lock) != 0)) {
        state = smtc_state;
        CRYPTO_THREAD_unlock(smtc_state_lock);
    } else {
        state = -1;
    }

    return state;
}

static void smtc_set_state(int state)
{
    if (ossl_assert(CRYPTO_THREAD_write_lock(smtc_state_lock) != 0)) {
        smtc_state = state;
        CRYPTO_THREAD_unlock(smtc_state_lock);
    }
}

static int get_bit(const unsigned char *buf, int m)
{
    if (m < 0)
        return 0;

    return (buf[m / 8] << (m % 8) >> 7) & 1;
}

/*
 * GM/T 0105-2021 Appendix D.3, Adaptive Proportion Test
 */
static int ossl_smtc_rng_poweron_test(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int res = 0, i;
    int W = 1024, C = 670, cnt;
    unsigned char buf[W / 8];
    size_t left = sizeof(buf);
    size_t len, entropy_len;
    int sample;
    unsigned char *entropy = NULL;
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *ctx = NULL;
    PROV_DRBG *drbg;

    OSSL_SELF_TEST_onbegin(st, "Poweron_RNG_Test", "RNG");

    rand = EVP_RAND_fetch(libctx, "HASH-DRBG", NULL);
    if (rand == NULL)
        goto end;

    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL)
        goto end;

    drbg = (PROV_DRBG *)ctx->algctx;
    if (drbg == NULL)
        goto end;

    while (left > 0) {
        entropy_len
            = ossl_prov_get_entropy(drbg->provctx, &entropy, left * 8,
                                    drbg->min_entropylen, drbg->max_entropylen);
        if (entropy_len == 0)
            goto end;

        len = entropy_len > left ? left : entropy_len;
        memcpy(buf + (sizeof(buf) - left), entropy, len);
        left -= len;

        ossl_prov_cleanup_entropy(drbg->provctx, entropy, entropy_len);
        entropy = NULL;
    }

    sample = get_bit(buf, 0);
    cnt = 1;

    for (i = 1; i < W; i++) {
        int cur = get_bit(buf, i);
        if (cur == sample) {
            cnt++;
            if (cnt >= C)
                goto end;
        } else {
            sample = cur;
            cnt = 1;
        }
    }

    res = 1;
end:
    OSSL_SELF_TEST_onend(st, res);
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    return res;
}

/* This API is triggered either on loading of the SMTC module or on demand */
int SELF_TEST_post(SELF_TEST_POST_PARAMS *st, int on_demand_test)
{
    int ok = 0;
    int loclstate;
    long checksum_len;
    long pass_len, salt_len;
    OSSL_CORE_BIO *bio_module = NULL;
    unsigned char *module_checksum = NULL;
    unsigned char *password = NULL, *salt = NULL;
    OSSL_SELF_TEST *ev = NULL;

    if (!RUN_ONCE(&smtc_self_test_init, do_smtc_self_test_init))
        return 0;

    if (!CRYPTO_THREAD_write_lock(self_test_lock))
        return 0;
    if (!CRYPTO_THREAD_read_lock(smtc_state_lock)) {
        CRYPTO_THREAD_unlock(self_test_lock);
        return 0;
    }
    if (smtc_state == SMTC_STATE_INIT) {
        CRYPTO_THREAD_unlock(smtc_state_lock);
        smtc_set_state(SMTC_STATE_SELFTEST_WHILE_IN_INIT);
        loclstate = SMTC_STATE_SELFTEST_WHILE_IN_INIT;
    } else if (smtc_state == SMTC_STATE_RUNNING) {
        CRYPTO_THREAD_unlock(smtc_state_lock);
        smtc_set_state(SMTC_STATE_SELFTEST_WHILE_RUNNING);
        loclstate = SMTC_STATE_SELFTEST_WHILE_RUNNING;
    } else {
        CRYPTO_THREAD_unlock(smtc_state_lock);
        CRYPTO_THREAD_unlock(self_test_lock);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        return 0;
    }

    if (st == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
        goto end;
    }

    ev = OSSL_SELF_TEST_new(st->cb, st->cb_arg);
    if (ev == NULL)
        goto end;

#ifndef OPENSSL_NO_SMTC_DEBUG
    if (st->verify_mac == NULL || atoi(st->verify_mac) != 0)
#endif
    {
        if (st->module_filename == NULL || st->module_checksum_data == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
            goto end;
        }

        bio_module = ossl_prov_bio_new_file(st->module_filename, "rb");
        module_checksum = OPENSSL_hexstr2buf(st->module_checksum_data,
                                             &checksum_len);
        if (bio_module == NULL || module_checksum == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
            goto end;
        }

        if (!verify_integrity(bio_module, ossl_prov_bio_read_ex,
                              module_checksum, checksum_len, st->libctx,
                              ev, OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MODULE_INTEGRITY_FAILURE);
            goto end;
        }
    }

    if (loclstate == SMTC_STATE_SELFTEST_WHILE_IN_INIT) {
        if ((st->rng_poweron_test == NULL
            || atoi(st->rng_poweron_test) != 0)
                && !ossl_smtc_rng_poweron_test(ev, st->libctx)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
            goto end;
        }

        if ((st->randomness_poweron_test == NULL
            || atoi(st->randomness_poweron_test) != 0)
                && !smtc_randomness_test_poweron(ev, st->libctx)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
            goto end;
        }
    } else { // SMTC_STATE_SELFTEST_WHILE_RUNNING
        if (!smtc_randomness_test_single(ev, st->libctx)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
            goto end;
        }
    }

    if (!SELF_TEST_kats(ev, st->libctx)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
        goto end;
    }

#ifndef OPENSSL_NO_SMTC_DEBUG
    if (st->verify_pass == NULL || atoi(st->verify_pass) != 0)
#endif
    if (loclstate == SMTC_STATE_SELFTEST_WHILE_IN_INIT) {
        if (st->admin_pass == NULL || st->admin_salt == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
            goto end;
        }

        password = OPENSSL_hexstr2buf(st->admin_pass, &pass_len);
        salt = OPENSSL_hexstr2buf(st->admin_salt, &salt_len);
        if (password == NULL || salt == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
            goto end;
        }

        if (!verify_password(st->libctx, password, pass_len, salt, salt_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
            goto end;
        }
    }
    ok = 1;
end:
    OPENSSL_free(password);
    OPENSSL_free(salt);
    OSSL_SELF_TEST_free(ev);
    OPENSSL_free(module_checksum);

    if (st != NULL)
        ossl_prov_bio_free(bio_module);

    if (ok)
        smtc_set_state(SMTC_STATE_RUNNING);
    else
        smtc_set_state(SMTC_STATE_ERROR);
    CRYPTO_THREAD_unlock(self_test_lock);

    return ok;
}

int smtc_prov_is_running(void)
{
    int res;

    if (!CRYPTO_THREAD_read_lock(smtc_state_lock))
        return 0;
    res = smtc_state == SMTC_STATE_RUNNING
            || smtc_state == SMTC_STATE_SELFTEST_WHILE_IN_INIT
            || smtc_state == SMTC_STATE_SELFTEST_WHILE_RUNNING;
    CRYPTO_THREAD_unlock(smtc_state_lock);
    return res;
}
