/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/sm3.h>
#include <openssl/hmac.h>
#include "internal/cryptlib.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/proverr.h>
#include "crypto/evp.h"
#include "crypto/rand.h"
#include "internal/e_os.h"
#include "internal/thread_once.h"
#include "prov/providercommon.h"
#include "prov/seeding.h"
#include "prov/bio.h"
#include "smtckey.h"
#include "self_test.h"
#include "self_test_rand.h"
#include "../implementations/rands/drbg_local.h"
#include "crypto/evp/evp_local.h"
#include "crypto/evp/legacy_meth.h"

/* The size of a temp buffer used to read in data */
#define INTEGRITY_BUF_SIZE  4096
#define SMTC_PASSWD_LEN     64
#define SMTC_AUTH_SALT_LEN  64
#define SMTC_AUTH_KEY_LEN   64

#define SMTC_AUTH_ID        "SMTC"
#define SMTC_AUTH_TEXT1     "login"
#define SMTC_AUTH_TEXT2     "_admin_"

#define SMTC_AUTH_TIMEOUT   60

static int SMTC_conditional_error_check = 1;
static CRYPTO_RWLOCK *self_test_lock = NULL;
static CRYPTO_RWLOCK *smtc_state_lock = NULL;
static int smtc_state = SMTC_STATE_INIT;
static unsigned char pubkey[] = SMTC_KEY_STRING;
static unsigned char smtc_passwd[] = {SMTC_DEFAULT_PASSWORD_ELEMENTS};

#ifndef OPENSSL_NO_ATF_SLIBCE
IMPLEMENT_LEGACY_EVP_MD_METH(sm3_sw, SM3)
static EVP_MD *sm3_md = NULL;
static const EVP_MD *sw_sm3_md(void)
{
    if (sm3_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sm3, NID_SM2_with_SM3)) == NULL
            || !EVP_MD_meth_set_result_size(md, SM3_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SM3_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SM3_CTX))
            || !EVP_MD_meth_set_flags(md, 0)
            || !EVP_MD_meth_set_init(md, sm3_sw_init)
            || !EVP_MD_meth_set_update(md, sm3_sw_update)
            || !EVP_MD_meth_set_final(md, sm3_sw_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        sm3_md = md;
    }
    return sm3_md;
}

static int sw_digests(ENGINE *e, const EVP_MD **digest,
                              const int **nids, int nid)
{
    static int digest_nids[2] = { NID_sm3, 0};
    int ok = 1;
    if (!digest) {
        *nids = digest_nids;
        return OSSL_NELEM(digest_nids);
    }

    switch (nid) {
    case NID_sm3:
        *digest = sw_sm3_md();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }

    return ok;
}

static CRYPTO_ONCE engine_atf_slibce = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(init_engine_atf_slibce)
{
    int ok = 0;
    ENGINE *engine = NULL;

# ifdef OPENSSL_NO_DYNAMIC_ENGINE
    extern ENGINE *engine_atf_slibce_load(const char* engine_name);
    engine = engine_atf_slibce_load("atf_slibce");
# else
    engine = ENGINE_by_id("atf_slibce");
# endif
    if (engine == NULL)
        return 0;

    if(!ENGINE_ctrl_cmd_string(engine, "engine_load", NULL, 0)) {
        OSSL_TRACE(SMTC, "Failed to execute cmd: engine_load\n");
        goto end;
    }

    if(!ENGINE_ctrl_cmd_string(engine, "engine_alloc_prsrc", NULL, 0)) {
        OSSL_TRACE(SMTC, "Failed to execute cmd: engine_alloc_prsrc\n");
        goto end;
    }

    if(!ENGINE_ctrl_cmd_string(engine, "engine_enable_sm2", NULL, 0)) {
        OSSL_TRACE(SMTC, "Failed to execute cmd: engine_enable_sm2\n");
        goto end;
    }

    if(!ENGINE_ctrl_cmd_string(engine, "engine_enable_sm4", NULL, 0)) {
        OSSL_TRACE(SMTC, "Failed to execute cmd: engine_enable_sm4\n");
        goto end;
    }

    if(!ENGINE_ctrl_cmd_string(engine, "engine_enable_asym_kek", NULL, 0)) {
        OSSL_TRACE(SMTC, "Failed to execute cmd: engine_enable_asym_kek\n");
        goto end;
    }

    if(!ENGINE_ctrl_cmd_string(engine, "engine_enable_kek", NULL, 0)) {
        OSSL_TRACE(SMTC, "Failed to execute cmd: engine_enable_kek\n");
        goto end;
    }

    if(!ENGINE_ctrl_cmd_string(engine, "engine_enable_kgen_kek", NULL, 0)) {
        OSSL_TRACE(SMTC, "Failed to execute cmd: engine_enable_kgen_kek\n");
        goto end;
    }

    if (!ENGINE_set_digests(engine, sw_digests))
        goto end;

    if (!ENGINE_set_default_pkey_meths(engine))
        goto end;

    ok = 1;
end:
# ifdef OPENSSL_NO_DYNAMIC_ENGINE
    if (ok == 0)
# endif
    {
        ENGINE_free(engine);
    }
    return ok;
}
#endif

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
 * Verify the signatre(SM2withSM3) of data read using a BIO and read_cb, and
 * verify the result matches the expected value.
 * Return 1 if verified, or 0 if it fails.
 */
static int verify_integrity(OSSL_CORE_BIO *bio,
                            OSSL_FUNC_BIO_read_ex_fn read_ex_cb,
                            unsigned char *expected, size_t expected_len,
                            OSSL_LIB_CTX *libctx, OSSL_SELF_TEST *ev)
{
    int ok = 0, status;
    BIO *pkey_bio = NULL;
    unsigned char buf[INTEGRITY_BUF_SIZE];
    size_t bytes_read = 0;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY *pkey = NULL;

    OSSL_SELF_TEST_onbegin(ev, OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY,
                           OSSL_SELF_TEST_DESC_INTEGRITY_VERIFY);

    pkey_bio = BIO_new_mem_buf(pubkey, sizeof(pubkey));
    if (pkey_bio == NULL)
        goto end;

    pkey = PEM_read_bio_PUBKEY_ex(pkey_bio, NULL, NULL, NULL, libctx, NULL);
    if (pkey == NULL)
        goto end;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;

    if (EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey) != 1)
        goto end;

    while (1) {
        status = read_ex_cb(bio, buf, sizeof(buf), &bytes_read);
        if (status != 1)
            break;
        if (EVP_DigestVerifyUpdate(mctx, buf, bytes_read) != 1)
            goto end;
    }

    OSSL_SELF_TEST_oncorrupt_byte(ev, expected);

    if (EVP_DigestVerifyFinal(mctx, expected, expected_len) != 1)
        goto end;

    ok = 1;
end:
    BIO_free(pkey_bio);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mctx);
    OSSL_SELF_TEST_onend(ev, ok);
    return ok;
}

#define PASSWD_BUF_SIZE 1024

static int do_auth(time_t ts, const char *text2, unsigned char *mac,
                   size_t mac_len, const unsigned char *mac_key,
                   size_t mac_key_len)
{
    int ok = 0;
    time_t now = time(NULL);
    char buf[128];
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    int buflen;

    if (ts > now || now - ts > SMTC_AUTH_TIMEOUT)
        return 0;

    if (text2 == NULL || strcmp(text2, SMTC_AUTH_TEXT2) != 0)
        return 0;

    buflen = snprintf(buf, sizeof(buf), "%ld%s%s", ts, SMTC_AUTH_ID,
                      SMTC_AUTH_TEXT1);
    if (buflen < 0 || buflen >= (int)sizeof(buf))
        return 0;

    if (HMAC(EVP_sm3(), mac_key, mac_key_len, (const unsigned char *)buf,
             buflen, md, &md_len) == NULL)
        goto end;

    if (md_len != mac_len || memcmp(md, mac, md_len) != 0) {
        OSSL_TRACE(SMTC, "Incorrect password\n");
        goto end;
    }

    ok = 1;
end:
    return ok;
}

static int verify_password(OSSL_LIB_CTX *libctx, const char *conf_key,
                           const char *conf_salt, const char *kek_file,
                           const char *eng)
{
    int ok = 0;
    time_t ts;
    unsigned char buf[128];
    unsigned char *mac_key = NULL, *salt = NULL;
    long mac_key_len, salt_len;
    char passphrase[SMTC_PASSWD_LEN];
    unsigned char key[SMTC_AUTH_KEY_LEN];
    unsigned char mkey[SMTC_AUTH_KEY_LEN];
    int buflen, keklen;
    size_t outlen;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen;
    ENGINE *engine = NULL;
    BIO *bio = NULL, *kekbio = NULL;
    EVP_PKEY *pkek = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char kekbuf[4096];

    if (conf_key == NULL && conf_salt == NULL) {
        if (EVP_read_pw_string(passphrase, sizeof(passphrase),
                               "Enter password: ", 0) != 0)
            goto end;

        if (memcmp(passphrase, smtc_passwd, sizeof(smtc_passwd)) != 0) {
            OSSL_TRACE(SMTC, "Incorrect password\n");
            goto end;
        }

        ok = 1;
        goto end;
    }

    if (conf_key == NULL || conf_salt == NULL)
        goto end;

    mac_key = OPENSSL_hexstr2buf(conf_key, &mac_key_len);
    if (mac_key == NULL)
        goto end;

    salt = OPENSSL_hexstr2buf(conf_salt, &salt_len);
    if (salt == NULL || salt_len != SMTC_AUTH_SALT_LEN)
        goto end;

    ts = time(NULL);

    if (EVP_read_pw_string(passphrase, sizeof(passphrase), "Enter password: ",
        0) != 0)
        goto end;

    if (PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, salt_len,
                          10000, EVP_sm3(), sizeof(key), key) != 1)
        goto end;

    buflen = snprintf((char *)buf, sizeof(buf), "%ld%s%s", ts, SMTC_AUTH_ID,
                      SMTC_AUTH_TEXT1);
    if (buflen < 0 || buflen >= (int)sizeof(buf))
        goto end;

    if (HMAC(EVP_sm3(), key, sizeof(key), buf, buflen, mac, &maclen) == NULL)
        goto end;

    if (eng) {
        engine = ENGINE_by_id(eng);
        if (engine == NULL) {
            OSSL_TRACE1(SMTC, "Can't load engine %s\n", eng);
            goto end;
        }
    }

    kekbio = BIO_new_file(kek_file, "rb");
    if (kekbio == NULL) {
        OSSL_TRACE1(SMTC, "Can't open auth kek file %s\n", kek_file);
        goto end;
    }

    keklen = BIO_read(kekbio, kekbuf, sizeof(kekbuf) - 1);
    BIO_free(kekbio);

    if (keklen <= 0) {
        OSSL_TRACE1(SMTC, "Error reading auth kek %s\n", kek_file);
        goto end;
    }

    kekbuf[keklen] = '\0';

    /*
     * atf_slibce engine doesn't support ENGINE_load_private_key(), use
     * PEM_read_bio_PrivateKey() instead
     */
#ifdef OPENSSL_NO_ATF_SLIBCE
    if (engine) {
        pkek = ENGINE_load_private_key(engine, (const char *)kekbuf, NULL,
                                       NULL);
    } else {
#endif
        bio = BIO_new_mem_buf((const void *)kekbuf, keklen);
        if (bio == NULL)
            goto end;

        pkek = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
#ifdef OPENSSL_NO_ATF_SLIBCE
    }
#endif

    if (pkek == NULL)
        goto end;

    ctx = EVP_PKEY_CTX_new(pkek, engine);
    if (ctx == NULL)
        goto end;

    outlen = sizeof(mkey);

    if (EVP_PKEY_decrypt_init(ctx) != 1
        || EVP_PKEY_decrypt(ctx, mkey, &outlen, mac_key, mac_key_len) != 1
        || outlen != sizeof(mkey))
        goto end;

    if (do_auth(ts, SMTC_AUTH_TEXT2, mac, maclen, mkey, outlen) != 1)
        goto end;

    ok = 1;
end:
    if (!ok) {
        OSSL_TRACE(SMTC, "Authentication failed\n");
        OSSL_syslog(LOG_ERR, "[SMTC] Admin login failed!\n");
        ossl_sleep(3000);
    } else {
        OSSL_syslog(LOG_INFO, "[SMTC] Admin login success\n");
    }
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(mac_key);
    OPENSSL_free(salt);
    ENGINE_free(engine);
    EVP_PKEY_free(pkek);
    BIO_free_all(bio);
    return ok;
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

    if (state == SMTC_STATE_ERROR) {
        OSSL_syslog(LOG_ERR, "[SMTC] SMTC module entering error state\n");
    } else if (state == SMTC_STATE_RUNNING) {
        OSSL_syslog(LOG_INFO, "[SMTC] SMTC module ready\n");
    }
}

/*
 * GM/T 0105-2021 Appendix D.3, Adaptive Proportion Test
 */
static ossl_unused int smtc_adaptive_proportion_test(
    const unsigned char *entropy, size_t len, int W, int C)
{
    size_t i;
    int cnt = 0;
    unsigned char sample = 0;

    if (entropy == NULL)
        return 0;

    for (i = 0; i < len; i++) {
        if (i % W == 0) {
            sample = entropy[i];
            cnt = 1;
        } else if (entropy[i] == sample) {
            cnt++;
            if (cnt >= C)
                return 0;
        }
    }

    return 1;
}

static int ossl_smtc_rng_poweron_test(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int ok = 0;
    unsigned char *entropy = NULL;
    size_t ret = 0;
#if defined(OPENSSL_RAND_SEED_RTCODE) || defined(OPENSSL_RAND_SEED_RTMEM) \
    || defined(OPENSSL_RAND_SEED_RTSOCK)
    size_t len = 1024, W = 512, C = 13;
#endif

    OSSL_SELF_TEST_onbegin(st, "Poweron_RNG_Test", "RNG");

#if defined(OPENSSL_RAND_SEED_RTCODE)
    ret = ossl_rand_get_entropy_from_source(RAND_ENTROPY_SOURCE_RTCODE,
                                            &entropy, 0, len, len);
    if (ret == len) {
        if (!smtc_adaptive_proportion_test(entropy, len, W, C))
            goto end;
    } else {
        goto end;
    }

    ossl_rand_cleanup_entropy(NULL, entropy, len);
    entropy = NULL;
#endif

#if defined(OPENSSL_RAND_SEED_RTMEM)
    entropy = NULL;
    ret = ossl_rand_get_entropy_from_source(RAND_ENTROPY_SOURCE_RTMEM,
                                            &entropy, 0, len, len);
    if (ret == len) {
        if (!smtc_adaptive_proportion_test(entropy, len, W, C))
            goto end;
    } else {
        goto end;
    }

    ossl_rand_cleanup_entropy(NULL, entropy, len);
    entropy = NULL;
#endif

#if defined(OPENSSL_RAND_SEED_RTSOCK)
    ret = ossl_rand_get_entropy_from_source(RAND_ENTROPY_SOURCE_RTSOCK,
                                            &entropy, 0, len, len);
    if (ret == len) {
        if (!smtc_adaptive_proportion_test(entropy, len, W, C))
            goto end;
    } else {
        goto end;
    }

    ossl_rand_cleanup_entropy(NULL, entropy, len);
    entropy = NULL;
#endif

    ok = 1;
#if defined(OPENSSL_RAND_SEED_RTCODE) || defined(OPENSSL_RAND_SEED_RTMEM) \
    || defined(OPENSSL_RAND_SEED_RTSOCK)
end:
#endif
    if (entropy) {
        ossl_rand_cleanup_entropy(NULL, entropy, ret);
        entropy = NULL;
    }

    OSSL_SELF_TEST_onend(st, ok);
    return ok;
}

/* This API is triggered either on loading of the SMTC module or on demand */
int SELF_TEST_post(SELF_TEST_POST_PARAMS *st, int on_demand_test)
{
    int ok = 0;
    int loclstate;
    long siglen;
    OSSL_CORE_BIO *bio_module = NULL;
    unsigned char *module_sig = NULL;
    OSSL_SELF_TEST *ev = NULL;

    if (!RUN_ONCE(&smtc_self_test_init, do_smtc_self_test_init))
        return 0;

#ifndef OPENSSL_NO_ATF_SLIBCE
    if (!RUN_ONCE(&engine_atf_slibce, init_engine_atf_slibce)) {
        OSSL_TRACE(SMTC, "Failed to load atf_slibce engine\n");
        goto end;
    }
#endif

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
    if (st->verify_sig == NULL || atoi(st->verify_sig) != 0)
#endif
    {
        if (st->module_filename == NULL || st->module_sig == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
            goto end;
        }

        bio_module = ossl_prov_bio_new_file(st->module_filename, "rb");
        module_sig = OPENSSL_hexstr2buf(st->module_sig, &siglen);
        if (bio_module == NULL || module_sig == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
            goto end;
        }

        if (!verify_integrity(bio_module, ossl_prov_bio_read_ex, module_sig,
                              siglen, st->libctx, ev)) {
            OSSL_TRACE(SMTC, "Module integrity verification failed\n");
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
                && (!smtc_rand_poweron_test(ev, 0)
#ifdef SDF_LIB
                    || !smtc_rand_poweron_test(ev, 1)
#endif
                    )) {
            ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
            goto end;
        }
    } else { // SMTC_STATE_SELFTEST_WHILE_RUNNING
        if (!smtc_rand_single_test(ev, 0)
#ifdef SDF_LIB
            || !smtc_rand_single_test(ev, 1)
#endif
            ) {
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
        if (!verify_password(st->libctx, st->auth_key, st->auth_salt, st->kek,
                             st->eng)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INCORRECT_PASSWORD);
            goto end;
        }
    }
    ok = 1;
end:
    OSSL_SELF_TEST_free(ev);
    OPENSSL_free(module_sig);

    if (st != NULL)
        ossl_prov_bio_free(bio_module);

    if (ok) {
        OSSL_syslog(LOG_INFO, "[SMTC] Self-test passed\n");
        smtc_set_state(SMTC_STATE_RUNNING);
    } else {
        OSSL_syslog(LOG_ERR, "[SMTC] Self-test failed\n");
        smtc_set_state(SMTC_STATE_ERROR);
    }
    CRYPTO_THREAD_unlock(self_test_lock);

    return ok;
}

void SELF_TEST_disable_conditional_error_state(void)
{
    SMTC_conditional_error_check = 0;
}

void ossl_set_error_state(const char *type)
{
    int cond_test = (type != NULL && strcmp(type, OSSL_SELF_TEST_TYPE_PCT) == 0);

    if (!cond_test || (SMTC_conditional_error_check == 1)) {
        smtc_set_state(SMTC_STATE_ERROR);
        ERR_raise(ERR_LIB_PROV, PROV_R_SMTC_MODULE_ENTERING_ERROR_STATE);
    } else {
        ERR_raise(ERR_LIB_PROV, PROV_R_SMTC_MODULE_CONDITIONAL_ERROR);
    }
}

int ossl_prov_is_running(void)
{
    int res;

    if (!RUN_ONCE(&smtc_self_test_init, do_smtc_self_test_init))
        return 0;

    if (!CRYPTO_THREAD_read_lock(smtc_state_lock))
        return 0;
    res = smtc_state == SMTC_STATE_RUNNING
            || smtc_state == SMTC_STATE_SELFTEST_WHILE_IN_INIT
            || smtc_state == SMTC_STATE_SELFTEST_WHILE_RUNNING;
    CRYPTO_THREAD_unlock(smtc_state_lock);
    return res;
}
