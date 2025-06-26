/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
/*
 * A test implementation for a hybrid KEM combining DH with SM2Curve and ML-KEM-768
 * key management functions
 */
#include "internal/deprecated.h"

#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include "crypto/ec.h"
#include "crypto/sm2dh_mlkem768_hybrid.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/param_build_set.h"

static OSSL_FUNC_keymgmt_new_fn                     sm2dh_mlkem768_hybrid_new_data;
static OSSL_FUNC_keymgmt_free_fn                    sm2dh_mlkem768_hybrid_free_data;
static OSSL_FUNC_keymgmt_gen_init_fn                sm2dh_mlkem768_hybrid_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn          sm2dh_mlkem768_hybrid_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn     sm2dh_mlkem768_hybrid_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn                     sm2dh_mlkem768_hybrid_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn             sm2dh_mlkem768_hybrid_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_template_fn        sm2dh_mlkem768_hybrid_gen_set_template;
static OSSL_FUNC_keymgmt_gettable_params_fn         sm2dh_mlkem768_hybrid_gettable_params;
static OSSL_FUNC_keymgmt_get_params_fn              sm2dh_mlkem768_hybrid_get_params;
static OSSL_FUNC_keymgmt_settable_params_fn         sm2dh_mlkem768_hybrid_settable_params;
static OSSL_FUNC_keymgmt_set_params_fn              sm2dh_mlkem768_hybrid_set_params;
static OSSL_FUNC_keymgmt_has_fn                     sm2dh_mlkem768_hybrid_has;
static OSSL_FUNC_keymgmt_import_fn                  sm2dh_mlkem768_hybrid_import;
static OSSL_FUNC_keymgmt_import_types_fn            sm2dh_mlkem768_hybrid_import_types;
static OSSL_FUNC_keymgmt_export_fn                  sm2dh_mlkem768_hybrid_export;
static OSSL_FUNC_keymgmt_export_types_fn            sm2dh_mlkem768_hybrid_export_types;
static OSSL_FUNC_keymgmt_query_operation_name_fn    sm2dh_mlkem768_hybrid_query_operation_name;

struct sm2dh_mlkem768_hybrid_gen_ctx {
    OSSL_LIB_CTX * libctx;
    int set_peer;
    sm2dh_mlkem768_hybrid_key * peer_key;
};

void * sm2dh_mlkem768_hybrid_new_data(void * provctx)
{
    if (!ossl_prov_is_running())
        return NULL;
    return sm2dh_mlkem768_hybrid_key_new();
}

static void sm2dh_mlkem768_hybrid_free_data(void * keydata)
{
    sm2dh_mlkem768_hybrid_key_free(keydata);
}

static void * sm2dh_mlkem768_hybrid_gen_init(void * provctx, int selection, const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct sm2dh_mlkem768_hybrid_gen_ctx * gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;
    
    if ((gctx = OPENSSL_zalloc(sizeof(* gctx))) != NULL) {
        gctx->libctx = libctx;
    }

    gctx->set_peer = 0;
    gctx->peer_key = NULL;

    return gctx;
}

static int sm2dh_mlkem768_hybrid_gen_set_params(void * genctx, const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM * sm2dh_mlkem768_hybrid_gen_settable_params(ossl_unused void * genctx, ossl_unused void * provctx)
{
    static OSSL_PARAM settable[] = { 
        OSSL_PARAM_END
    };

    return settable;
}

static void * sm2dh_mlkem768_hybrid_gen(void * genctx, OSSL_CALLBACK * osslcb, void * cbarg)
{
    int ret = 0;
    struct sm2dh_mlkem768_hybrid_gen_ctx * gctx = genctx;

    sm2dh_mlkem768_hybrid_key * hybrid_key = sm2dh_mlkem768_hybrid_key_new();
    if(!hybrid_key)
        goto err;

    hybrid_key->libctx = gctx->libctx;
    
    /* distinguish client and server */
    if(gctx->set_peer)
    {
        /* server side, the shared secret has been generated now */
        if(!sm2dh_mlkem768_hybrid_encaps(gctx->libctx, hybrid_key->ss, SM2_DH_MLKEM_768_HYBRID_SS_SIZE, hybrid_key->ct, SM2_DH_MLKEM_768_HYBRID_CT_SIZE, gctx->peer_key->pk, SM2_DH_MLKEM_768_HYBRID_PK_SIZE))
            goto err;
    }
    else
    {
        /* client side: only client generates the KEM private key and sets has_kem_sk = 1 */
        if(!sm2dh_mlkem768_hybrid_keygen(gctx->libctx, hybrid_key->pk, SM2_DH_MLKEM_768_HYBRID_PK_SIZE, hybrid_key->sk, SM2_DH_MLKEM_768_HYBRID_SK_SIZE))
            goto err;
        hybrid_key->has_kem_sk = 1;
    }

    ret = 1;
    if(ret)
        return hybrid_key;
err:
    sm2dh_mlkem768_hybrid_key_free(hybrid_key);
    return NULL;
}

static void sm2dh_mlkem768_hybrid_gen_cleanup(void * genctx)
{
    struct sm2dh_mlkem768_hybrid_gen_ctx * gctx = genctx;
    if (gctx == NULL)
        return;
    if (gctx->peer_key != NULL)
        sm2dh_mlkem768_hybrid_key_free(gctx->peer_key);
    OPENSSL_free(gctx);
}

static int sm2dh_mlkem768_hybrid_gen_set_template(void * genctx, void * template)
{
    int ret = 0;
    sm2dh_mlkem768_hybrid_key * template_hybrid_key = template;
    struct sm2dh_mlkem768_hybrid_gen_ctx * gctx = genctx;
  
    if(template == NULL)
        return 1;
    if(gctx == NULL)
        goto err;
    
    gctx->set_peer = 1;
    gctx->peer_key = sm2dh_mlkem768_hybrid_key_new();

    if(gctx->peer_key == NULL)
        goto err;

    gctx->peer_key->libctx = gctx->libctx;

    if(gctx->peer_key->pk == NULL || template_hybrid_key->pk == NULL)
        goto err;

    memcpy(gctx->peer_key->pk, template_hybrid_key->pk, SM2_DH_MLKEM_768_HYBRID_PK_SIZE);

    ret = 1;
    return ret;
err:
    gctx->set_peer = 0;
    if(gctx->peer_key != NULL)
    {
        sm2dh_mlkem768_hybrid_key_free(gctx->peer_key);
    }
    return ret;
}

static const OSSL_PARAM sm2_mlkem_hybrid_known_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM * sm2dh_mlkem768_hybrid_gettable_params(ossl_unused void * provctx)
{
    return sm2_mlkem_hybrid_known_gettable_params;
}

int sm2dh_mlkem768_hybrid_get_params(void * key, OSSL_PARAM params[])
{
    int ret = 0;
    OSSL_PARAM * p;
    sm2dh_mlkem768_hybrid_key * hybrid_key = key;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, SM2_DH_MLKEM_768_HYBRID_PK_SIZE + SM2_DH_MLKEM_768_HYBRID_SK_SIZE))
        goto err;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, 256))
        goto err;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL) {
        if (!OSSL_PARAM_set_int(p, 128))
            goto err;
    }
    /* encode the public key or ciphertext */
    if((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        if(hybrid_key->has_kem_sk) {
            /* client: encode the public key from hybrid_key */
            if(!OSSL_PARAM_set_octet_string(p, hybrid_key->pk, SM2_DH_MLKEM_768_HYBRID_PK_SIZE))
                goto err;
        } else {
            /* server: encode the ciphertext from hybrid_key */
            if(!OSSL_PARAM_set_octet_string(p, hybrid_key->ct, SM2_DH_MLKEM_768_HYBRID_CT_SIZE))
                goto err;
        }
    }

    ret = 1;
err:
    return ret;
}

static const OSSL_PARAM sm2dh_mlkem768_hybrid_known_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM * sm2dh_mlkem768_hybrid_settable_params(void * provctx)
{
    return sm2dh_mlkem768_hybrid_known_settable_params;
}

static int sm2dh_mlkem768_hybrid_set_params(void * key, const OSSL_PARAM params[])
{
    const OSSL_PARAM * p;
    int ret = 0;
    unsigned char * buf = NULL;
    size_t buf_len = 0;

    sm2dh_mlkem768_hybrid_key * hybrid_key = key;
    if (hybrid_key == NULL || hybrid_key->ct == NULL || hybrid_key->pk == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if(p != NULL) {
        if(!OSSL_PARAM_get_octet_string(p, (void **)&buf, 0, &buf_len))
            return 0;

        /*  
            Note: Use a flag to determine client or server side.
            But the behaviour of ssl_generate_param_group shoule be checked.
        */
        if(hybrid_key->has_kem_sk){
            if(buf_len != SM2_DH_MLKEM_768_HYBRID_PK_SIZE)
                goto err;
            memcpy(hybrid_key->pk, buf, SM2_DH_MLKEM_768_HYBRID_PK_SIZE);
        } else {
            if(buf_len != SM2_DH_MLKEM_768_HYBRID_CT_SIZE)
                goto err;
            memcpy(hybrid_key->ct, buf, SM2_DH_MLKEM_768_HYBRID_CT_SIZE);
        }       
    }
    ret = 1;
err:
    if(buf)
        OPENSSL_free(buf);
    return ret;
}

static int sm2dh_mlkem768_hybrid_has(const void * keydata, int selection)
{
    const sm2dh_mlkem768_hybrid_key * hybrid_key = keydata;
    int ok = 1;

    if (!ossl_prov_is_running() || hybrid_key == NULL)
        return 0;

    /* (TODO) add flags indicating the existances of public key and private key */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (hybrid_key->pk != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (hybrid_key->has_kem_sk);

    /*
     * We consider OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS to always be
     * available, so no extra check is needed other than the previous one
     * against EC_POSSIBLE_SELECTIONS.
     */
    return ok;
}


int sm2dh_mlkem768_hybrid_import(void * keydata, int selection, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!ossl_prov_is_running() || keydata == NULL)
        return 0;
    return ok;
}

static const OSSL_PARAM * sm2dh_mlkem768_hybrid_import_types(int selection)
{
    return NULL;
}

static int sm2dh_mlkem768_hybrid_export(void * keydata, int selection, OSSL_CALLBACK * param_cb, void * cbarg)
{
    int ok = 1;
    OSSL_PARAM_BLD * bld = NULL;
    OSSL_PARAM * params = NULL;
    /*
    EC_KEY * dummy_ec_key = NULL;
    BN_CTX * bnctx = NULL;
    const sm2dh_mlkem768_hybrid_key * hybrid_key = keydata;
    unsigned char * genbuf = NULL;
    */

    if (!ossl_prov_is_running() || keydata == NULL)
        return 0;
    
    bld = OSSL_PARAM_BLD_new();
    if( bld == NULL )
        return 0;
       
    /*
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        dummy_ec_key = EC_KEY_new_by_curve_name_ex(hybrid_key->libctx, NULL, NID_sm2);
        bnctx = BN_CTX_new_ex(hybrid_key->libctx);
        if (bnctx == NULL) {
            ok = 0;
            goto end;
        }
        BN_CTX_start(bnctx);
        ok = ok && ossl_ec_group_todata(EC_KEY_get0_group(dummy_ec_key), bld, NULL,
                                        hybrid_key->libctx,
                                        ossl_ec_key_get0_propq(dummy_ec_key),
                                        bnctx, &genbuf);
    }
    */

    if (ok && (params = OSSL_PARAM_BLD_to_param(bld)) != NULL)
        ok = param_cb(params, cbarg); 

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    /*
    if(dummy_ec_key)
        EC_KEY_free(dummy_ec_key);
    OPENSSL_free(genbuf);
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    */
    return ok;
}

static const OSSL_PARAM * sm2dh_mlkem768_hybrid_export_types(int selection)
{
    return NULL;
}

static const char * sm2dh_mlkem768_hybrid_query_operation_name(int operation_id)
{
    switch (operation_id) {
        case OSSL_OP_KEYEXCH:
            return "SM2DH-MLKEM768-HYBRID";
    }
    return NULL;   
}

const OSSL_DISPATCH ossl_sm2dh_mlkem768_hybrid_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                        (void (*)(void))sm2dh_mlkem768_hybrid_new_data },
    { OSSL_FUNC_KEYMGMT_FREE,                       (void (*)(void))sm2dh_mlkem768_hybrid_free_data },
    { OSSL_FUNC_KEYMGMT_GEN,                        (void (*)(void))sm2dh_mlkem768_hybrid_gen },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,        (void (*)(void))sm2dh_mlkem768_hybrid_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,                   (void (*)(void))sm2dh_mlkem768_hybrid_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,             (void (*)(void))sm2dh_mlkem768_hybrid_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                (void (*)(void))sm2dh_mlkem768_hybrid_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,           (void (*)(void))sm2dh_mlkem768_hybrid_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,            (void (*)(void))sm2dh_mlkem768_hybrid_gettable_params },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,                 (void (*)(void))sm2dh_mlkem768_hybrid_get_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,            (void (*)(void))sm2dh_mlkem768_hybrid_settable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,                 (void (*)(void))sm2dh_mlkem768_hybrid_set_params },
    { OSSL_FUNC_KEYMGMT_HAS,                        (void (*)(void))sm2dh_mlkem768_hybrid_has },
    { OSSL_FUNC_KEYMGMT_IMPORT,                     (void (*)(void))sm2dh_mlkem768_hybrid_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,               (void (*)(void))sm2dh_mlkem768_hybrid_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,                     (void (*)(void))sm2dh_mlkem768_hybrid_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,               (void (*)(void))sm2dh_mlkem768_hybrid_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,       (void (*)(void))sm2dh_mlkem768_hybrid_query_operation_name },
    { 0, NULL }
};
