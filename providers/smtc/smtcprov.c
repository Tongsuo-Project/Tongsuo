/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include "internal/cryptlib.h"
#include "prov/implementations.h"
#include "prov/bio.h"
#include "prov/names.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/provider_util.h"
#include "prov/seeding.h"
#include "self_test.h"
#include "internal/core.h"
#include "internal/smtc_names.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn smtc_gettable_params;
static OSSL_FUNC_provider_get_params_fn smtc_get_params;
static OSSL_FUNC_provider_query_operation_fn smtc_query;

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=smtc", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

#ifdef STATIC_SMTC
OSSL_provider_init_fn ossl_smtc_provider_init;
# define OSSL_provider_init_int ossl_smtc_provider_init
#endif

/*
 * Should these function pointers be stored in the provider side provctx? Could
 * they ever be different from one init to the next? We assume not for now.
 */
static BIO *bio_err = NULL;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params;

static OSSL_FUNC_self_test_cb_fn *c_stcbfn = NULL;

typedef struct smtc_global_st {
    const OSSL_CORE_HANDLE *handle;
    SELF_TEST_POST_PARAMS selftest_params;
} SMTC_GLOBAL;

static void *smtc_prov_ossl_ctx_new(OSSL_LIB_CTX *libctx)
{
    SMTC_GLOBAL *fgbl = OPENSSL_zalloc(sizeof(*fgbl));

    if (fgbl == NULL)
        return NULL;

    return fgbl;
}

static void smtc_prov_ossl_ctx_free(void *fgbl)
{
    OPENSSL_free(fgbl);
}

static const OSSL_LIB_CTX_METHOD smtc_prov_ossl_ctx_method = {
    OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY,
    smtc_prov_ossl_ctx_new,
    smtc_prov_ossl_ctx_free,
};


/* Parameters we provide to the core */
static const OSSL_PARAM smtc_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static int smtc_get_params_from_core(SMTC_GLOBAL *fgbl)
{
    OSSL_PARAM core_params[11], *p = core_params;

    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_MODULE_PATH,
            (char **)&fgbl->selftest_params.module_filename,
            sizeof(fgbl->selftest_params.module_filename));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_MODULE_MAC,
            (char **)&fgbl->selftest_params.module_checksum_data,
            sizeof(fgbl->selftest_params.module_checksum_data));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_SHOW_SELFTEST,
            (char **)&fgbl->selftest_params.show_selftest,
            sizeof(fgbl->selftest_params.show_selftest));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_ADMIN_PASS,
            (char **)&fgbl->selftest_params.admin_pass,
            sizeof(fgbl->selftest_params.admin_pass));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_ADMIN_SALT,
            (char **)&fgbl->selftest_params.admin_salt,
            sizeof(fgbl->selftest_params.admin_salt));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_RNG_POWERON_TEST,
            (char **)&fgbl->selftest_params.rng_poweron_test,
            sizeof(fgbl->selftest_params.rng_poweron_test));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_RNG_CONTINUOUS_TEST,
            (char **)&fgbl->selftest_params.rng_continuous_test,
            sizeof(fgbl->selftest_params.rng_continuous_test));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_RANDOMNESS_POWERON_TEST,
            (char **)&fgbl->selftest_params.randomness_poweron_test,
            sizeof(fgbl->selftest_params.randomness_poweron_test));
#ifndef OPENSSL_NO_SMTC_DEBUG
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_MODULE_VERIFY_MAC,
            (char **)&fgbl->selftest_params.verify_mac,
            sizeof(fgbl->selftest_params.verify_mac));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_SMTC_PARAM_MODULE_VERIFY_PASS,
            (char **)&fgbl->selftest_params.verify_pass,
            sizeof(fgbl->selftest_params.verify_pass));
#endif
    *p = OSSL_PARAM_construct_end();

    if (!c_get_params(fgbl->handle, core_params)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *smtc_gettable_params(void *provctx)
{
    return smtc_param_types;
}

static int smtc_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Tongsuo SMTC Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TONGSUO_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TONGSUO_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, smtc_prov_is_running()))
        return 0;
    return 1;
}

static int self_test_events(const OSSL_PARAM params[], void *arg)
{
    char *self_test_corrupt_desc = NULL;
    char *self_test_corrupt_type = NULL;
    const OSSL_PARAM *p = NULL;
    const char *phase = NULL, *type = NULL, *desc = NULL;
    int ret = 0;

    if (bio_err == NULL) {
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
        if (bio_err == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_PHASE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    phase = (const char *)p->data;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_DESC);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    desc = (const char *)p->data;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_TYPE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    type = (const char *)p->data;

    if (strcmp(phase, OSSL_SELF_TEST_PHASE_START) == 0)
        BIO_printf(bio_err, "%s : (%s) : %s\n", desc, type, phase);
    else if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) == 0
                || strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) == 0)
        BIO_printf(bio_err, "%s : (%s) : %s\n", desc, type, phase);
    /*
     * The self test code will internally corrupt the KAT test result if an
     * error is returned during the corrupt phase.
     */
    if (strcmp(phase, OSSL_SELF_TEST_PHASE_CORRUPT) == 0
            && (self_test_corrupt_desc != NULL
                || self_test_corrupt_type != NULL)) {
        if (self_test_corrupt_desc != NULL
                && strcmp(self_test_corrupt_desc, desc) != 0)
            goto end;
        if (self_test_corrupt_type != NULL
                && strcmp(self_test_corrupt_type, type) != 0)
            goto end;
        BIO_printf(bio_err, "%s : (%s) : %s\n", desc, type, phase);
        goto err;
    }
end:
    ret = 1;
err:
    return ret;
}

static void set_self_test_cb(SMTC_GLOBAL *fgbl)
{
    if (fgbl->selftest_params.show_selftest != NULL
        && atoi(fgbl->selftest_params.show_selftest) != 0)
        OSSL_SELF_TEST_set_callback(fgbl->selftest_params.libctx,
                                    self_test_events, NULL);

    if (c_stcbfn != NULL) {
        c_stcbfn((OPENSSL_CORE_CTX *)fgbl->selftest_params.libctx,
                 &fgbl->selftest_params.cb,
                 &fgbl->selftest_params.cb_arg);
    } else {
        fgbl->selftest_params.cb = NULL;
        fgbl->selftest_params.cb_arg = NULL;
    }
}

static int smtc_self_test(void *provctx)
{
    SMTC_GLOBAL *fgbl = ossl_lib_ctx_get_data(ossl_prov_ctx_get0_libctx(provctx),
                                            OSSL_LIB_CTX_SMTC_PROV_INDEX,
                                            &smtc_prov_ossl_ctx_method);

    set_self_test_cb(fgbl);
    return SELF_TEST_post(&fgbl->selftest_params, 1) ? 1 : 0;
}

/*
 * For the algorithm names, we use the following formula for our primary
 * names:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD series).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 *
 * We add diverse other names where applicable, such as the names that
 * NIST uses, or that are used for ASN.1 OBJECT IDENTIFIERs, or names
 * we have used historically.
 */
static const OSSL_ALGORITHM smtc_digests[] = {
    { PROV_NAMES_SHA2_256, "provider=smtc", ossl_sha256_functions },
#ifndef OPENSSL_NO_SM3
    { PROV_NAMES_SM3, "provider=smtc", ossl_sm3_functions },
#endif /* OPENSSL_NO_SM3 */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM_CAPABLE smtc_ciphers[] = {
#ifndef OPENSSL_NO_SM4
    ALG(PROV_NAMES_SM4_CBC, ossl_sm4128cbc_functions),
    ALG(PROV_NAMES_SM4_GCM, ossl_sm4128gcm_functions),
#endif /* OPENSSL_NO_SM4 */
    {{NULL, NULL, NULL}, NULL}};

static OSSL_ALGORITHM exported_ciphers[OSSL_NELEM(smtc_ciphers)];

static const OSSL_ALGORITHM smtc_macs[] = {
    {PROV_NAMES_GMAC, "provider=smtc", ossl_gmac_functions},
    {PROV_NAMES_HMAC, "provider=smtc", ossl_hmac_functions},
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM smtc_kdfs[] = {
    { PROV_NAMES_TLS1_PRF, "provider=smtc", ossl_kdf_tls1_prf_functions },
    /* used by SM2 encryption and decryption */
    { PROV_NAMES_X963KDF, "provider=smtc", ossl_kdf_x963_kdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM smtc_rands[] = {
    { PROV_NAMES_HASH_DRBG, "provider=smtc", ossl_drbg_hash_functions },
    { PROV_NAMES_TEST_RAND, "provider=smtc", ossl_test_rng_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM smtc_keyexch[] = {
#ifndef OPENSSL_NO_SM2
    { PROV_NAMES_SM2DH, "provider=smtc", ossl_sm2dh_keyexch_functions },
#endif
    { PROV_NAMES_TLS1_PRF, "provider=smtc", ossl_kdf_tls1_prf_keyexch_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM smtc_signature[] = {
    { PROV_NAMES_RSA, "provider=smtc", ossl_rsa_signature_functions },
# ifndef OPENSSL_NO_SM2
    { PROV_NAMES_SM2, "provider=smtc", ossl_sm2_signature_functions },
# endif
    { PROV_NAMES_HMAC, "provider=smtc", ossl_mac_legacy_hmac_signature_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM smtc_asym_cipher[] = {
    { PROV_NAMES_RSA, "provider=smtc", ossl_rsa_asym_cipher_functions },
#ifndef OPENSSL_NO_SM2
    { PROV_NAMES_SM2, "provider=smtc", ossl_sm2_asym_cipher_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM smtc_asym_kem[] = {
    { PROV_NAMES_RSA, "provider=smtc", ossl_rsa_asym_kem_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM smtc_keymgmt[] = {
    { PROV_NAMES_RSA, "provider=smtc", ossl_rsa_keymgmt_functions,
      PROV_DESCS_RSA },
#ifndef OPENSSL_NO_SM2
    { PROV_NAMES_SM2, "provider=smtc", ossl_sm2_keymgmt_functions,
      PROV_DESCS_SM2 },
#endif
    /* TLCP create HMAC, such as ECC-SM2-SM4-CBC-SM3 */
    { PROV_NAMES_HMAC, "provider=default", ossl_mac_legacy_keymgmt_functions,
      PROV_DESCS_HMAC_SIGN },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM smtc_decoder[] = {
#define DECODER_PROVIDER "smtc"
#include "../decoders.inc"
    { NULL, NULL, NULL }
#undef DECODER_PROVIDER
};

static const OSSL_ALGORITHM *smtc_query(void *provctx, int operation_id,
                                        int *no_cache)
{
    *no_cache = 0;

    if (!ossl_prov_is_running())
        return NULL;

    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return smtc_digests;
    case OSSL_OP_CIPHER:
        return exported_ciphers;
    case OSSL_OP_MAC:
        return smtc_macs;
    case OSSL_OP_KDF:
        return smtc_kdfs;
    case OSSL_OP_RAND:
        return smtc_rands;
    case OSSL_OP_KEYMGMT:
        return smtc_keymgmt;
    case OSSL_OP_KEYEXCH:
        return smtc_keyexch;
    case OSSL_OP_SIGNATURE:
        return smtc_signature;
    case OSSL_OP_ASYM_CIPHER:
        return smtc_asym_cipher;
    case OSSL_OP_KEM:
        return smtc_asym_kem;
    case OSSL_OP_DECODER:
        return smtc_decoder;
    }
    return NULL;
}

static void smtc_intern_teardown(void *provctx)
{
    BIO_free(bio_err);
    /*
     * We know that the library context is the same as for the outer provider,
     * so no need to destroy it here.
     */
    BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx));
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH smtc_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))smtc_intern_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))smtc_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))smtc_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))smtc_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))ossl_prov_get_capabilities },
    { OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))smtc_self_test },
    { 0, NULL }
};

int OSSL_provider_init_int(const OSSL_CORE_HANDLE *handle,
                           const OSSL_DISPATCH *in,
                           const OSSL_DISPATCH **out,
                           void **provctx)
{
    int ret;
    SMTC_GLOBAL *fgbl;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_FUNC_core_get_libctx_fn *c_internal_get_libctx = NULL;
    SELF_TEST_POST_PARAMS selftest_params;

    memset(&selftest_params, 0, sizeof(selftest_params));

    if (!ossl_prov_bio_from_dispatch(in)
            || !ossl_prov_seeding_from_dispatch(in))
        return 0;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_internal_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        case OSSL_FUNC_SELF_TEST_CB:
            c_stcbfn = OSSL_FUNC_self_test_cb(in);
            break;
        default:
            break;
        }
    }

    if (c_internal_get_libctx == NULL)
        return 0;

    libctx = (OSSL_LIB_CTX *)c_internal_get_libctx(handle);

    /* Use SM3-DRBG */
    ret = RAND_set_DRBG_type(libctx, "HASH-DRBG", NULL, NULL, "SM3");
    if (ret != 1)
        return 0;

    if ((*provctx = ossl_prov_ctx_new()) == NULL
            || (corebiometh = ossl_bio_prov_init_bio_method()) == NULL) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }

    if ((fgbl = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_SMTC_PROV_INDEX,
                                      &smtc_prov_ossl_ctx_method)) == NULL)
        goto err;

    fgbl->handle = handle;

    /*
     * We did initial set up of selftest_params in a local copy, because we
     * could not create fgbl until c_CRYPTO_zalloc was defined in the loop
     * above.
     */
    fgbl->selftest_params = selftest_params;
    fgbl->selftest_params.libctx = libctx;

    set_self_test_cb(fgbl);

    if (!smtc_get_params_from_core(fgbl)) {
        /* Error already raised */
        goto err;
    }

    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_core_bio_method(*provctx, corebiometh);

    *out = smtc_dispatch_table;
    ossl_prov_cache_exported_algorithms(smtc_ciphers, exported_ciphers);
    return 1;
err:
    smtc_intern_teardown(*provctx);
    *provctx = NULL;
    OSSL_LIB_CTX_free(libctx);
    return 0;
}
