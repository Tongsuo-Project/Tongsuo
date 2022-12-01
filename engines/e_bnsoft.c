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

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>

/* Engine Id and Name */
static const char *engine_bnsoft_id = "bnsoft";
static const char *engine_bnsoft_name = "Tongsuo Test engine support";

static BN_METHOD *bn_method = NULL;
static BN_CTX *bn_ctx = NULL;

/* Engine Lifetime functions */
static int bnsoft_destroy(ENGINE *e);
static int bnsoft_init(ENGINE *e);
static int bnsoft_finish(ENGINE *e);

static int bn_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    return BN_mod_add(r, a, b, m, bn_ctx);
}

static int bn_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    return BN_mod_sub(r, a, b, m, bn_ctx);
}

static int bn_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    return BN_mod_mul(r, a, b, m, bn_ctx);
}

static int bn_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx)
{
    return BN_mod_exp(r, a, p, m, bn_ctx);
}

static int bn_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    return BN_mod_sqr(r, a, m, bn_ctx);
}

static int bn_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    return BN_div(dv, rem, m, d, bn_ctx);
}

static BIGNUM *bn_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    return BN_mod_sqrt(r, a, n, bn_ctx);
}

static BIGNUM *bn_inverse(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    return BN_mod_inverse(r, a, n, bn_ctx);
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_bnsoft(ENGINE *e)
{
    bn_method = BN_METHOD_new("test");
    if (bn_method == NULL)
        return 0;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return 0;

    if (!ENGINE_set_id(e, engine_bnsoft_id)
        || !ENGINE_set_name(e, engine_bnsoft_name)
#ifndef OPENSSL_NO_BN_METHOD
        || !ENGINE_set_bn_meth(e, bn_method)
#endif
        || !ENGINE_set_destroy_function(e, bnsoft_destroy)
        || !ENGINE_set_init_function(e, bnsoft_init)
        || !ENGINE_set_finish_function(e, bnsoft_finish)) {
        return 0;
    }

    return 1;
}

static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_bnsoft_id) != 0))
        return 0;
    if (!bind_bnsoft(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

static int bnsoft_init(ENGINE *e)
{
    BN_METHOD_set_add(bn_method, bn_add);
    BN_METHOD_set_sub(bn_method, bn_sub);
    BN_METHOD_set_mul(bn_method, bn_mul);
    BN_METHOD_set_exp(bn_method, bn_exp);
    BN_METHOD_set_sqr(bn_method, bn_sqr);
    BN_METHOD_set_div(bn_method, bn_div);
    BN_METHOD_set_sqrt(bn_method, bn_sqrt);
    BN_METHOD_set_inverse(bn_method, bn_inverse);

    return 1;
}

static int bnsoft_finish(ENGINE *e)
{
    return 1;
}

static int bnsoft_destroy(ENGINE *e)
{
    BN_CTX_free(bn_ctx);
    BN_METHOD_free(bn_method);
    return 1;
}
