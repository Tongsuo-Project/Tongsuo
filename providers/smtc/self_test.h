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
    const char *module_checksum_data;       /* Expected module MAC integrity */
    const char *show_selftest;              /* Output selftest results */
    const char *admin_pass;                 /* Admin password */
    const char *admin_salt;                 /* Salt of password */
    const char *rng_poweron_test;           /* 熵源上电健康测试 */
    const char *rng_continuous_test;        /* 熵源连续健康测试 */
    const char *randomness_poweron_test;    /* 随机数上电自检 */
#ifndef OPENSSL_NO_SMTC_DEBUG
    const char *verify_mac;
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
