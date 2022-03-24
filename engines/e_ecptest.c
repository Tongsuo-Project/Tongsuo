/*
 * Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/md5.h>
#include <openssl/sm3.h>

/* Engine Id and Name */
static const char *engine_ecptest_id = "ecptest";
static const char *engine_ecptest_name = "OpenSSL Test engine support";


/* Engine Lifetime functions */
static int ecptest_destroy(ENGINE *e);
static int ecptest_init(ENGINE *e);
static int ecptest_finish(ENGINE *e);

/* Setup ecp_meths */
#ifndef OPENSSL_NO_EC
static void destroy_ecp_meths(void);
static int ecptest_ecp_meths(ENGINE *e, const EC_POINT_METHOD **meth,
                             const int **cids, int cid);
static int ecp_scalars_mul(const EC_GROUP *group, EC_POINT *r[], size_t num,
                           const EC_POINT *points[], const BIGNUM *scalars[],
                           BN_CTX *ctx);
static int ecp_scalar_mul(const EC_GROUP *group, EC_POINT *r[], size_t num,
                          const EC_POINT *points[], const BIGNUM *scalar,
                          BN_CTX *ctx);
static int ecp_strings_to_points(const EC_GROUP *group, EC_POINT *r[],
                                 size_t num, const unsigned char *strings[],
                                 BN_CTX *ctx);
static int ecp_strings_to_points_scalar_mul(const EC_GROUP *group,
                                            EC_POINT *r[], size_t num,
                                            const unsigned char *strings[],
                                            const BIGNUM *scalar,
                                            BN_CTX *ctx);
#endif

static int bind_ecptest(ENGINE *e)
{
    /* Ensure the ecptest error handling is set up */

    if (!ENGINE_set_id(e, engine_ecptest_id)
        || !ENGINE_set_name(e, engine_ecptest_name)
#ifndef OPENSSL_NO_EC
        || !ENGINE_set_ecp_meths(e, ecptest_ecp_meths)
#endif
        || !ENGINE_set_destroy_function(e, ecptest_destroy)
        || !ENGINE_set_init_function(e, ecptest_init)
        || !ENGINE_set_finish_function(e, ecptest_finish)) {
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_ecptest_id) != 0))
        return 0;
    if (!bind_ecptest(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

static int ecptest_init(ENGINE *e)
{
    return 1;
}

static int ecptest_finish(ENGINE *e)
{
    return 1;
}

static int ecptest_destroy(ENGINE *e)
{
#ifndef OPENSSL_NO_EC
    destroy_ecp_meths();
#endif
    return 1;
}

#ifndef OPENSSL_NO_SM3
static unsigned char *SM3(const unsigned char *in, size_t inl, unsigned char *out)
{
    int outl;
    const EVP_MD *md;
    EVP_MD_CTX *mctx = NULL;
    unsigned char *ret = NULL;
    static unsigned char m[SM3_DIGEST_LENGTH];

    md = EVP_sm3();
    if (!md)
        goto err;

    mctx = EVP_MD_CTX_new();
    if (!mctx)
        goto err;

    if (!EVP_DigestInit(mctx, md))
        goto err;

    if (!EVP_DigestUpdate(mctx, in, inl))
        goto err;

    if (!out)
        out = m;

    if (!EVP_DigestFinal(mctx, out, (unsigned int*)&outl))
        goto err;

    ret = out;
err:
    EVP_MD_CTX_free(mctx);

    return ret;
}
#endif

/* Setup ecp_meths */
#ifndef OPENSSL_NO_EC
static const EC_POINT_METHOD *_hidden_p256_meth = NULL;

static const EC_POINT_METHOD *ecp_method_p256(void)
{
    EC_POINT_METHOD *meth;

    if (!_hidden_p256_meth) {
        if ((meth = EC_POINT_METHOD_new(NID_X9_62_prime256v1)) == NULL)
            return NULL;

        EC_POINT_METHOD_set_scalars_mul(meth, ecp_scalars_mul);
        EC_POINT_METHOD_set_scalar_mul(meth, ecp_scalar_mul);
        EC_POINT_METHOD_set_strings_to_points(meth, ecp_strings_to_points);
        EC_POINT_METHOD_set_strings_to_points_scalar_mul(meth,
                                        ecp_strings_to_points_scalar_mul);

        _hidden_p256_meth = meth;
    }

    return _hidden_p256_meth;
}

# ifndef OPENSSL_NO_SM2
static const EC_POINT_METHOD *_hidden_sm2_meth = NULL;

static const EC_POINT_METHOD *ecp_method_sm2(void)
{
    EC_POINT_METHOD *meth;

    if (!_hidden_sm2_meth) {
        if ((meth = EC_POINT_METHOD_new(NID_sm2)) == NULL)
            return NULL;

        EC_POINT_METHOD_set_scalars_mul(meth, ecp_scalars_mul);
        EC_POINT_METHOD_set_scalar_mul(meth, ecp_scalar_mul);
        EC_POINT_METHOD_set_strings_to_points(meth, ecp_strings_to_points);
        EC_POINT_METHOD_set_strings_to_points_scalar_mul(meth,
                                        ecp_strings_to_points_scalar_mul);

        _hidden_sm2_meth = meth;
    }

    return _hidden_sm2_meth;
}
# endif

static void destroy_ecp_meths(void)
{
    EC_POINT_METHOD_free((EC_POINT_METHOD *)_hidden_p256_meth);
    _hidden_p256_meth = NULL;
# ifndef OPENSSL_NO_SM2
    EC_POINT_METHOD_free((EC_POINT_METHOD *)_hidden_sm2_meth);
    _hidden_sm2_meth = NULL;
# endif
}

static int ecptest_ecp_method_nids(const int **nids)
{
    static int ecp_method_nids[6] = { 0, 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EC_POINT_METHOD *meth;
        if ((meth = ecp_method_p256()) != NULL)
            ecp_method_nids[pos++] = NID_X9_62_prime256v1;
# ifndef OPENSSL_NO_SM2
        if ((meth = ecp_method_sm2()) != NULL)
            ecp_method_nids[pos++] = NID_sm2;
# endif
        ecp_method_nids[pos] = 0;
        init = 1;
    }
    *nids = ecp_method_nids;
    return pos;
}

static int ecptest_ecp_meths(ENGINE *e, const EC_POINT_METHOD **meth,
                             const int **cids, int cid)
{
    int ret = 1;

    if (!meth)
        return ecptest_ecp_method_nids(cids);

    switch (cid) {
    case NID_X9_62_prime256v1:
        *meth = ecp_method_p256();
        break;
# ifndef OPENSSL_NO_SM2
    case NID_sm2:
        *meth = ecp_method_sm2();
        break;
# endif
    default:
        ret = 0;
        *meth = NULL;
        break;
    }

    return ret;
}

static int ecp_scalars_mul(const EC_GROUP *group, EC_POINT *r[], size_t num,
                           const EC_POINT *points[], const BIGNUM *scalars[],
                           BN_CTX *ctx)
{
    int ret = 0;
    size_t i;
    BN_CTX *new_ctx = NULL;
    EC_GROUP *gp = NULL;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return ret;
    }

    if (!(gp = EC_GROUP_new_by_curve_name(EC_GROUP_get_curve_name(group))))
        goto err;

    for (i = 0; i < num; i++) {
        if (!EC_POINT_mul(gp, r[i], NULL, points[i], scalars[i], ctx))
            goto err;
    }

    ret = 1;
err:
    EC_GROUP_free(gp);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ecp_scalar_mul(const EC_GROUP *group, EC_POINT *r[], size_t num,
                          const EC_POINT *points[], const BIGNUM *scalar,
                          BN_CTX *ctx)
{
    int ret = 0;
    size_t i;
    BN_CTX *new_ctx = NULL;
    EC_GROUP *gp = NULL;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return ret;
    }

    if (!(gp = EC_GROUP_new_by_curve_name(EC_GROUP_get_curve_name(group))))
        goto err;

    for (i = 0; i < num; i++) {
        if (!EC_POINT_mul(gp, r[i], NULL, points[i], scalar, ctx))
            goto err;
    }

    ret = 1;
err:
    EC_GROUP_free(gp);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ecp_strings_to_points(const EC_GROUP *group, EC_POINT *r[],
                                 size_t num, const unsigned char *strings[],
                                 BN_CTX *ctx)
{
    int ret = 0;
    size_t i, len;
    unsigned char *hash = NULL;
    BIGNUM *b = NULL;
    BN_CTX *new_ctx = NULL;
    EC_GROUP *gp = NULL;
    const EC_POINT *G;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return ret;
    }

    gp = EC_GROUP_new_by_curve_name(EC_GROUP_get_curve_name(group));
    if (!gp)
        goto err;

    G = EC_GROUP_get0_generator(group);
    if (!G)
        goto err;

    for (i = 0; i < num; i++) {
# if !defined(OPENSSL_NO_SM3)
        len = SM3_DIGEST_LENGTH;
        hash = SM3(strings[i], strlen((char *)strings[i]), NULL);
# elif !defined(OPENSSL_NO_MD5)
        len = MD5_DIGEST_LENGTH;
        hash = MD5(strings[i], strlen((char *)strings[i]), NULL);
# endif
        if (!hash)
            goto err;

        if (!(b = BN_bin2bn(hash, len, NULL)))
            goto err;

        if (!EC_POINT_mul(gp, r[i], NULL, G, b, ctx))
            goto err;

        BN_free(b);
        b = NULL;
    }

    ret = 1;
err:
    BN_free(b);
    EC_GROUP_free(gp);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ecp_strings_to_points_scalar_mul(const EC_GROUP *group,
                                            EC_POINT *r[], size_t num,
                                            const unsigned char *strings[],
                                            const BIGNUM *scalar,
                                            BN_CTX *ctx)
{
    int ret = 0, len;
    size_t i;
    unsigned char *hash;
    BIGNUM *b = NULL;
    BN_CTX *new_ctx = NULL;
    EC_GROUP *gp = NULL;
    const EC_POINT *G;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return ret;
    }

    gp = EC_GROUP_new_by_curve_name(EC_GROUP_get_curve_name(group));
    if (!gp)
        goto err;

    G = EC_GROUP_get0_generator(group);
    if (!G)
        goto err;

    for (i = 0; i < num; i++) {
# if !defined(OPENSSL_NO_SM3)
        len = SM3_DIGEST_LENGTH;
        hash = SM3(strings[i], strlen((char *)strings[i]), NULL);
# elif !defined(OPENSSL_NO_MD5)
        len = MD5_DIGEST_LENGTH;
        hash = MD5(strings[i], strlen((char *)strings[i]), NULL);
# endif
        if (!hash)
            goto err;

        if (!(b = BN_bin2bn(hash, len, NULL)))
            goto err;

        if (!EC_POINT_mul(gp, r[i], scalar, G, b, ctx))
            goto err;

        BN_free(b);
        b = NULL;
    }

    ret = 1;
err:
    BN_free(b);
    EC_GROUP_free(gp);
    BN_CTX_free(new_ctx);
    return ret;
}
#endif
