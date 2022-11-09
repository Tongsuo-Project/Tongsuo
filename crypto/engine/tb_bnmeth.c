/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "eng_local.h"

static ENGINE_TABLE *bn_meth_table = NULL;
static int bn_meth_ex_data_idx = -1;
static const int dummy_nid = 1;

typedef struct bn_meth_data_ctx_st {
    const BN_METHOD *bn_meth;
} bn_meth_data_ctx;

static void bn_meth_data_ctx_free_func(void *parent, void *ptr,
                                       CRYPTO_EX_DATA *ad, int idx, long argl,
                                       void *argp)
{
    if (ptr) {
        bn_meth_data_ctx *ctx = (bn_meth_data_ctx *)ptr;
        OPENSSL_free(ctx);
    }
}

static int bn_meth_set_data_ctx(ENGINE *e, bn_meth_data_ctx **ctx)
{
    int ret = 1;
    bn_meth_data_ctx *c;

    if (!RUN_ONCE(&engine_lock_init, do_engine_lock_init)) {
        ENGINEerr(ENGINE_F_BN_METH_SET_DATA_CTX, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    c = OPENSSL_zalloc(sizeof(*c));
    if (c == NULL) {
        ENGINEerr(ENGINE_F_BN_METH_SET_DATA_CTX, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!CRYPTO_THREAD_write_lock(global_engine_lock)) {
        OPENSSL_free(c);
        return 0;
    }

    if ((*ctx = (bn_meth_data_ctx *)ENGINE_get_ex_data(e, bn_meth_ex_data_idx))
        == NULL) {
        /* Good, we're the first */
        ret = ENGINE_set_ex_data(e, bn_meth_ex_data_idx, c);
        if (ret) {
            *ctx = c;
            c = NULL;
        }
    }
    CRYPTO_THREAD_unlock(global_engine_lock);
    OPENSSL_free(c);
    return ret;
}

/*
 * This function retrieves the context structure from an ENGINE's "ex_data",
 * or if it doesn't exist yet, sets it up.
 */
static bn_meth_data_ctx *bn_meth_get_data_ctx(ENGINE *e)
{
    bn_meth_data_ctx *ctx;

    if (bn_meth_ex_data_idx < 0) {
        /*
         * Create and register the ENGINE ex_data, and associate our "free"
         * function with it to ensure any allocated contexts get freed when
         * an ENGINE goes underground.
         */
        int new_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL,
                                              bn_meth_data_ctx_free_func);
        if (new_idx == -1) {
            ENGINEerr(ENGINE_F_BN_METH_GET_DATA_CTX, ENGINE_R_NO_INDEX);
            return NULL;
        }

        if (!RUN_ONCE(&engine_lock_init, do_engine_lock_init)) {
            ENGINEerr(ENGINE_F_BN_METH_GET_DATA_CTX, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        if (!CRYPTO_THREAD_write_lock(global_engine_lock))
            return NULL;

        /* Avoid a race by checking again inside this lock */
        if (bn_meth_ex_data_idx < 0) {
            /* Good, someone didn't beat us to it */
            bn_meth_ex_data_idx = new_idx;
            new_idx = -1;
        }
        CRYPTO_THREAD_unlock(global_engine_lock);
        /*
         * In theory we could "give back" the index here if (new_idx>-1), but
         * it's not possible and wouldn't gain us much if it were.
         */
    }
    ctx = (bn_meth_data_ctx *)ENGINE_get_ex_data(e, bn_meth_ex_data_idx);
    /* Check if the context needs to be created */
    if ((ctx == NULL) && !bn_meth_set_data_ctx(e, &ctx))
        /* "set_data" will set errors if necessary */
        return NULL;
    return ctx;
}

static void engine_unregister_all_bn_meth(void)
{
    engine_table_cleanup(&bn_meth_table);
}

void ENGINE_unregister_bn_meth(ENGINE *e)
{
    engine_table_unregister(&bn_meth_table, e);
}

int ENGINE_register_bn_meth(ENGINE *e)
{
    if (ENGINE_get_bn_meth(e))
        return engine_table_register(&bn_meth_table,
                                     engine_unregister_all_bn_meth, e,
                                     &dummy_nid, 1, 0);
    return 1;
}

void ENGINE_register_all_bn_meth(void)
{
    ENGINE *e;

    for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))
        ENGINE_register_bn_meth(e);
}

int ENGINE_set_default_bn_meth(ENGINE *e)
{
    if (ENGINE_get_bn_meth(e))
        return engine_table_register(&bn_meth_table,
                                     engine_unregister_all_bn_meth, e,
                                     &dummy_nid, 1, 1);
    return 1;
}

ENGINE *ENGINE_get_default_bn_meth(void)
{
    return ossl_engine_table_select(&bn_meth_table, dummy_nid,
                                    OPENSSL_FILE, OPENSSL_LINE);
}

const BN_METHOD *ENGINE_get_bn_meth(ENGINE *e)
{
    bn_meth_data_ctx *ctx = bn_meth_get_data_ctx(e);
    if (ctx == NULL)
        return NULL;
    return ctx->bn_meth;
}

int ENGINE_set_bn_meth(ENGINE *e, const BN_METHOD *bn_meth)
{
    bn_meth_data_ctx *ctx = bn_meth_get_data_ctx(e);
    if (ctx == NULL)
        return 0;
    ctx->bn_meth = bn_meth;
    return 1;
}

