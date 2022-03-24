/*
 * Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include "eng_local.h"

static ENGINE_TABLE *ecpmeth_table = NULL;
static int ecpmeth_ex_data_idx = -1;

typedef struct ecpmeth_data_ctx_st {
    /* ecpmeth handling is via this callback */
    ENGINE_ECP_METHS_PTR ecpmeths;
} ecpmeth_data_ctx;

static void ecpmeth_data_ctx_free_func(void *parent, void *ptr,
                                       CRYPTO_EX_DATA *ad, int idx, long argl,
                                       void *argp)
{
    if (ptr) {
        ecpmeth_data_ctx *ctx = (ecpmeth_data_ctx *)ptr;
        OPENSSL_free(ctx);
    }
}

static int ecpmeth_set_data_ctx(ENGINE *e, ecpmeth_data_ctx **ctx)
{
    int ret = 1;
    ecpmeth_data_ctx *c;

    if (!RUN_ONCE(&engine_lock_init, do_engine_lock_init)) {
        ENGINEerr(ENGINE_F_ECPMETH_SET_DATA_CTX, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    c = OPENSSL_zalloc(sizeof(*c));
    if (c == NULL) {
        ENGINEerr(ENGINE_F_ECPMETH_SET_DATA_CTX, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    CRYPTO_THREAD_write_lock(global_engine_lock);
    if ((*ctx = (ecpmeth_data_ctx *)ENGINE_get_ex_data(e,
                                                       ecpmeth_ex_data_idx))
        == NULL) {
        /* Good, we're the first */
        ret = ENGINE_set_ex_data(e, ecpmeth_ex_data_idx, c);
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
static ecpmeth_data_ctx *ecpmeth_get_data_ctx(ENGINE *e)
{
    ecpmeth_data_ctx *ctx;

    if (ecpmeth_ex_data_idx < 0) {
        /*
         * Create and register the ENGINE ex_data, and associate our "free"
         * function with it to ensure any allocated contexts get freed when
         * an ENGINE goes underground.
         */
        int new_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL,
                                              ecpmeth_data_ctx_free_func);
        if (new_idx == -1) {
            ENGINEerr(ENGINE_F_ECPMETH_GET_DATA_CTX, ENGINE_R_NO_INDEX);
            return NULL;
        }

        if (!RUN_ONCE(&engine_lock_init, do_engine_lock_init)) {
            ENGINEerr(ENGINE_F_ECPMETH_GET_DATA_CTX, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        CRYPTO_THREAD_write_lock(global_engine_lock);
        /* Avoid a race by checking again inside this lock */
        if (ecpmeth_ex_data_idx < 0) {
            /* Good, someone didn't beat us to it */
            ecpmeth_ex_data_idx = new_idx;
            new_idx = -1;
        }
        CRYPTO_THREAD_unlock(global_engine_lock);
        /*
         * In theory we could "give back" the index here if (new_idx>-1), but
         * it's not possible and wouldn't gain us much if it were.
         */
    }
    ctx = (ecpmeth_data_ctx *)ENGINE_get_ex_data(e, ecpmeth_ex_data_idx);
    /* Check if the context needs to be created */
    if ((ctx == NULL) && !ecpmeth_set_data_ctx(e, &ctx))
        /* "set_data" will set errors if necessary */
        return NULL;
    return ctx;
}

static void engine_unregister_all_ecp_meths(void)
{
    engine_table_cleanup(&ecpmeth_table);
}

void ENGINE_unregister_ecp_meths(ENGINE *e)
{
    engine_table_unregister(&ecpmeth_table, e);
}

int ENGINE_register_ecp_meths(ENGINE *e)
{
    ENGINE_ECP_METHS_PTR fn = ENGINE_get_ecp_meths(e);
    if (fn) {
        const int *cids;
        int num_cids = fn(e, NULL, &cids, 0);
        if (num_cids > 0)
            return engine_table_register(&ecpmeth_table,
                                         engine_unregister_all_ecp_meths, e,
                                         cids, num_cids, 0);
    }
    return 1;
}

void ENGINE_register_all_ecp_meths(void)
{
    ENGINE *e;

    for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))
        ENGINE_register_ecp_meths(e);
}

int ENGINE_set_default_ecp_meths(ENGINE *e)
{
    ENGINE_ECP_METHS_PTR fn = ENGINE_get_ecp_meths(e);
    if (fn) {
        const int *cids;
        int num_cids = fn(e, NULL, &cids, 0);
        if (num_cids > 0)
            return engine_table_register(&ecpmeth_table,
                                         engine_unregister_all_ecp_meths, e,
                                         cids, num_cids, 1);
    }
    return 1;
}

/*
 * Exposed API function to get a functional reference from the implementation
 * table (ie. try to get a functional reference from the tabled structural
 * references).
 */
ENGINE *ENGINE_get_ecp_meth_engine(int curve_id)
{
    return engine_table_select(&ecpmeth_table, curve_id);
}

/* Obtains an EC_KEY implementation from an ENGINE functional reference */
const EC_POINT_METHOD *ENGINE_get_ecp_meth(ENGINE *e, int curve_id)
{
    const EC_POINT_METHOD *ret;
    ENGINE_ECP_METHS_PTR fn = ENGINE_get_ecp_meths(e);
    if (!fn || !fn(e, &ret, NULL, curve_id)) {
        ENGINEerr(ENGINE_F_ENGINE_GET_ECP_METH, ENGINE_R_UNIMPLEMENTED_ECP_METH);
        return NULL;
    }
    return ret;
}

/* Gets the pkey_meth callback from an ENGINE structure */
ENGINE_ECP_METHS_PTR ENGINE_get_ecp_meths(ENGINE *e)
{
    ecpmeth_data_ctx *ctx = ecpmeth_get_data_ctx(e);
    if (ctx == NULL)
        return NULL;
    return ctx->ecpmeths;
}

/* Sets the ecp_meth callback in an ENGINE structure */
int ENGINE_set_ecp_meths(ENGINE *e, ENGINE_ECP_METHS_PTR f)
{
    ecpmeth_data_ctx *ctx = ecpmeth_get_data_ctx(e);
    if (ctx == NULL)
        return 0;
    ctx->ecpmeths = f;
    return 1;
}

