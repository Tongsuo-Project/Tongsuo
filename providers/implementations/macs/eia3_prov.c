/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include <crypto/zuc.h>
#include "crypto/eia3/eia3_local.h"

#include "prov/implementations.h"
#include "prov/providercommon.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_FUNC_mac_newctx_fn eia3_new;
static OSSL_FUNC_mac_dupctx_fn eia3_dup;
static OSSL_FUNC_mac_freectx_fn eia3_free;
static OSSL_FUNC_mac_gettable_params_fn eia3_gettable_params;
static OSSL_FUNC_mac_get_params_fn eia3_get_params;
static OSSL_FUNC_mac_settable_ctx_params_fn eia3_settable_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn eia3_set_ctx_params;
static OSSL_FUNC_mac_init_fn eia3_init;
static OSSL_FUNC_mac_update_fn eia3_update;
static OSSL_FUNC_mac_final_fn eia3_final;

struct eia3_data_st {
    void *provctx;
    int updated;
    unsigned char key[ZUC_KEY_SIZE];
    unsigned char iv[ZUC_CTR_SIZE];
    EIA3_CTX eia3;
};

static void *eia3_new(void *provctx)
{
    struct eia3_data_st *ctx;

    if (!ossl_prov_is_running())
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void eia3_free(void *vmacctx)
{
    OPENSSL_free(vmacctx);
}

static void *eia3_dup(void *vsrc)
{
    struct eia3_data_st *src = vsrc;
    struct eia3_data_st *dst;

    if (!ossl_prov_is_running())
        return NULL;
    dst = OPENSSL_malloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    *dst = *src;
    return dst;
}

static size_t eia3_size(void)
{
    return EIA3_DIGEST_SIZE;
}

static int eia3_setkey(struct eia3_data_st *ctx,
                       const unsigned char *key, size_t keylen)
{
    if (keylen != EVP_ZUC_KEY_SIZE) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    EIA3_Init(&ctx->eia3, key, ctx->iv);
    memcpy(&ctx->key, key, keylen);
    ctx->updated = 0;
    return 1;
}

static int eia3_init(void *vmacctx, const unsigned char *key,
                     size_t keylen, const OSSL_PARAM params[])
{
    struct eia3_data_st *ctx = vmacctx;

    /* initialize the context in MAC_ctrl function */
    if (!ossl_prov_is_running() || !eia3_set_ctx_params(ctx, params))
        return 0;
    if (key != NULL)
        return eia3_setkey(ctx, key, keylen);
    /* no reinitialization of context with the same key is allowed */
    return ctx->updated == 0;
}

static int eia3_update(void *vmacctx, const unsigned char *data,
                       size_t datalen)
{
    struct eia3_data_st *ctx = vmacctx;

    ctx->updated = 1;
    if (datalen == 0)
        return 1;

    /* eia3 has nothing to return in its update function */
    EIA3_Update(&ctx->eia3, data, datalen);
    return 1;
}

static int eia3_final(void *vmacctx, unsigned char *out, size_t *outl,
                      size_t outsize)
{
    struct eia3_data_st *ctx = vmacctx;

    if (!ossl_prov_is_running())
        return 0;
    ctx->updated = 1;
    EIA3_Final(&ctx->eia3, out);
    *outl = eia3_size();
    return 1;
}

static const OSSL_PARAM known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *eia3_gettable_params(void *provctx)
{
    return known_gettable_params;
}

static int eia3_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, eia3_size());

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_IV, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *eia3_settable_ctx_params(ossl_unused void *ctx,
                                                  ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static int eia3_set_ctx_params(void *vmacctx, const OSSL_PARAM *params)
{
    struct eia3_data_st *ctx = vmacctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL
            && p->data_type == OSSL_PARAM_OCTET_STRING
            && !eia3_setkey(ctx, p->data, p->data_size))
        return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_IV)) != NULL
            && p->data_type == OSSL_PARAM_OCTET_STRING) {
        if (p->data_size != ZUC_CTR_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }

        memcpy(&ctx->iv, p->data, p->data_size);

        EIA3_Init(&ctx->eia3, ctx->key, ctx->iv);
        ctx->updated = 0;
    }

    return 1;
}

const OSSL_DISPATCH ossl_eia3_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))eia3_new },
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void))eia3_dup },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))eia3_free },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))eia3_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))eia3_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))eia3_final },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void))eia3_gettable_params },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))eia3_get_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))eia3_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))eia3_set_ctx_params },
    { 0, NULL }
};
