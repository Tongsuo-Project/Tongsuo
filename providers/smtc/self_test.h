/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/core_dispatch.h>
#include <openssl/types.h>
#include <openssl/self_test.h>

#define SMTC_STATE_INIT                      0
#define SMTC_STATE_SELFTEST_WHILE_IN_INIT    1
#define SMTC_STATE_RUNNING                   2
#define SMTC_STATE_SELFTEST_WHILE_RUNNING    3
#define SMTC_STATE_ERROR                     4

typedef struct self_test_post_params_st {
    const char *module_filename;            /* Module file to perform MAC on */
    const char *module_sig;                 /* Signature of module */
    const char *auth_key;                   /* key of HMAC, PBKDF(password, salt) */
    const char *auth_salt;                  /* Salt of PBKDF */
    const char *kek;                        /* key for encrypting HMAC key */
    const char *eng;                        /* Engine ID */
    const char *syslog;                     /* syslog switch */
    const char *rng_poweron_test;           /* Entropy power-on health test */
    const char *rng_continuous_test;        /* Entropy continuous health test */
    const char *randomness_poweron_test;    /* Random power-on self-test */
#ifndef OPENSSL_NO_SMTC_DEBUG
    const char *verify_sig;
    const char *verify_pass;
#endif

    OSSL_CALLBACK *cb;
    void *cb_arg;
    OSSL_LIB_CTX *libctx;
} SELF_TEST_POST_PARAMS;

int SELF_TEST_post(SELF_TEST_POST_PARAMS *st, int on_demand_test);
int SELF_TEST_kats(OSSL_SELF_TEST *event, OSSL_LIB_CTX *libctx);

void SELF_TEST_disable_conditional_error_state(void);
int smtc_prov_is_running(void);
int smtc_prov_get_state(void);
