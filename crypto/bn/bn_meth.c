/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include "bn_local.h"

/** Creates a new BN_METHOD object for the specified name
 *  \param  name  the method name
 *  \return newly created BN_METHOD object or NULL if an error occurred
 */
BN_METHOD *BN_METHOD_new(const char *name)
{
    BN_METHOD *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ret->name = OPENSSL_strdup(name);
    if (ret->name == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    return ret;
}

/** Frees a BN_METHOD object
 *  \param  meth  BN_METHOD object to be freed
 */
void BN_METHOD_free(BN_METHOD *meth)
{
    OPENSSL_free(meth->name);
    OPENSSL_free(meth);
}

/** Copies BN_METHOD object
 *  \param  dst  destination BN_METHOD object
 *  \param  src  source BN_METHOD object
 *  \return 1 on success and 0 if an error occurred
 */
int BN_METHOD_copy(BN_METHOD *dst, const BN_METHOD *src)
{
    char *name = NULL;
    if (dst == src)
        return 1;

    name = OPENSSL_strdup(src->name);
    if (name == NULL)
        return 0;

    if (dst->name)
        OPENSSL_free(dst->name);

    memcpy(dst, src, sizeof(*dst));
    dst->name = name;

    return 1;
}

/** Returns the name of a BN_METHOD object
 *  \param  meth  BN_METHOD object
 */
char *BN_METHOD_name(BN_METHOD *meth)
{
    return meth->name;
}

int (*BN_METHOD_get_add(BN_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    return meth->mod_add;
}

void BN_METHOD_set_add(BN_METHOD *meth,
                       int (*mod_add)(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                      const BIGNUM *m, BN_CTX *ctx))
{
    meth->mod_add = mod_add;
}

int (*BN_METHOD_get_sub(BN_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    return meth->mod_sub;
}

void BN_METHOD_set_sub(BN_METHOD *meth,
                       int (*mod_sub)(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                      const BIGNUM *m, BN_CTX *ctx))
{
    meth->mod_sub = mod_sub;
}

int (*BN_METHOD_get_mul(BN_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    return meth->mod_mul;
}

void BN_METHOD_set_mul(BN_METHOD *meth,
                       int (*mod_mul)(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                      const BIGNUM *m, BN_CTX *ctx))
{
    meth->mod_mul = mod_mul;
}

int (*BN_METHOD_get_exp(BN_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    return meth->mod_exp;
}

void BN_METHOD_set_exp(BN_METHOD *meth,
                       int (*mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                      const BIGNUM *m, BN_CTX *ctx))
{
    meth->mod_exp = mod_exp;
}

int (*BN_METHOD_get_sqr(BN_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    return meth->mod_sqr;
}

void BN_METHOD_set_sqr(BN_METHOD *meth,
                       int (*mod_sqr)(BIGNUM *r, const BIGNUM *a, const BIGNUM *m,
                                      BN_CTX *ctx))
{
    meth->mod_sqr = mod_sqr;
}

int (*BN_METHOD_get_div(BN_METHOD *meth))
    (BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    return meth->div;
}

void BN_METHOD_set_div(BN_METHOD *meth,
                       int (*div)(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                                  const BIGNUM *d, BN_CTX *ctx))
{
    meth->div = div;
}

BIGNUM *(*BN_METHOD_get_sqrt(BN_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    return meth->mod_sqrt;
}

void BN_METHOD_set_sqrt(BN_METHOD *meth,
                        BIGNUM *(*mod_sqrt)(BIGNUM *r, const BIGNUM *a,
                                            const BIGNUM *n, BN_CTX *ctx))
{
    meth->mod_sqrt = mod_sqrt;
}

BIGNUM *(*BN_METHOD_get_inverse(BN_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    return meth->mod_inverse;
}

void BN_METHOD_set_inverse(BN_METHOD *meth,
                           BIGNUM *(*mod_inverse)(BIGNUM *r, const BIGNUM *a,
                                                  const BIGNUM *n, BN_CTX *ctx))
{
    meth->mod_inverse = mod_inverse;
}
