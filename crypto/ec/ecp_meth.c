/*
 * Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include "ec_local.h"

/** Creates a new EC_POINT_METHOD object for the specified curve_id
 *  \param  curve_id  the elliptic curve id
 *  \return newly created EC_POINT_METHOD object or NULL if an error occurred
 */
EC_POINT_METHOD *EC_POINT_METHOD_new(int curve_id)
{
    EC_POINT_METHOD *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ret->curve_id = curve_id;

    return ret;
}

/** Frees a EC_POINT_METHOD object
 *  \param  meth  EC_POINT_METHOD object to be freed
 */
void EC_POINT_METHOD_free(EC_POINT_METHOD *meth)
{
    OPENSSL_free(meth);
}

/** Copies EC_POINT_METHOD object
 *  \param  dst  destination EC_POINT_METHOD object
 *  \param  src  source EC_POINT_METHOD object
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_METHOD_copy(EC_POINT_METHOD *dst, const EC_POINT_METHOD *src)
{
    if (dst == src)
        return 1;

    if (dst->curve_id != src->curve_id) {
        ECerr(EC_F_EC_POINT_METHOD_COPY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }

    memcpy(dst, src, sizeof(*dst));

    return 1;
}

/** Returns the curve_id of a EC_POINT_METHOD object
 *  \param  meth  EC_POINT_METHOD object
 *  \return NID of the curve name OID or 0 if not set.
 */
int EC_POINT_METHOD_curve_id(EC_POINT_METHOD *meth)
{
    return meth->curve_id;
}

int (*EC_POINT_METHOD_get_add(EC_POINT_METHOD *meth))
    (const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b,
     BN_CTX *)
{
    return meth->add;
}

void EC_POINT_METHOD_set_add(EC_POINT_METHOD *meth,
                             int (*add)(const EC_GROUP *, EC_POINT *r,
                                        const EC_POINT *a, const EC_POINT *b,
                                        BN_CTX *))
{
    meth->add = add;
}

int (*EC_POINT_METHOD_get_dbl(EC_POINT_METHOD *meth))
    (const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *)
{
    return meth->dbl;
}

void EC_POINT_METHOD_set_dbl(EC_POINT_METHOD *meth,
                             int (*dbl)(const EC_GROUP *, EC_POINT *r,
                                        const EC_POINT *a, BN_CTX *))
{
    meth->dbl = dbl;
}

int (*EC_POINT_METHOD_get_invert(EC_POINT_METHOD *meth))
    (const EC_GROUP *, EC_POINT *point, BN_CTX *)
{
    return meth->invert;
}

void EC_POINT_METHOD_set_invert(EC_POINT_METHOD *meth,
                                int (*invert)(const EC_GROUP *, EC_POINT *point,
                                              BN_CTX *))
{
    meth->invert = invert;
}

int (*EC_POINT_METHOD_get_mul(EC_POINT_METHOD *meth))
    (const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar, size_t num,
     const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *)
{
    return meth->mul;
}

void EC_POINT_METHOD_set_mul(EC_POINT_METHOD *meth,
                             int (*mul)(const EC_GROUP *group, EC_POINT *r,
                                        const BIGNUM *scalar, size_t num,
                                        const EC_POINT *points[],
                                        const BIGNUM *scalars[], BN_CTX *))
{
    meth->mul = mul;
}

int (*EC_POINT_METHOD_get_scalars_mul(EC_POINT_METHOD *meth))
    (const EC_GROUP *group, EC_POINT *r[], size_t num, const EC_POINT *points[],
     const BIGNUM *scalars[], BN_CTX *ctx)
{
    return meth->scalars_mul;
}

void EC_POINT_METHOD_set_scalars_mul(EC_POINT_METHOD *meth,
                                     int (*scalars_mul)(const EC_GROUP *group,
                                                        EC_POINT *r[], size_t num,
                                                        const EC_POINT *points[],
                                                        const BIGNUM *scalars[],
                                                        BN_CTX *ctx))
{
    meth->scalars_mul = scalars_mul;
}

int (*EC_POINT_METHOD_get_scalar_mul(EC_POINT_METHOD *meth))
    (const EC_GROUP *group, EC_POINT *r[], size_t num, const EC_POINT *points[],
     const BIGNUM *scalar, BN_CTX *ctx)
{
    return meth->scalar_mul;
}

void EC_POINT_METHOD_set_scalar_mul(EC_POINT_METHOD *meth,
                                    int (*scalar_mul)(const EC_GROUP *group,
                                                      EC_POINT *r[], size_t num,
                                                      const EC_POINT *points[],
                                                      const BIGNUM *scalar,
                                                      BN_CTX *ctx))
{
    meth->scalar_mul = scalar_mul;
}

int (*EC_POINT_METHOD_get_strings_to_points(EC_POINT_METHOD *meth))
    (const EC_GROUP *group, EC_POINT *r[], size_t num, const unsigned char *strings[],
     BN_CTX *ctx)
{
    return meth->strings_to_points;
}

void EC_POINT_METHOD_set_strings_to_points(EC_POINT_METHOD *meth,
                                           int (*func)(const EC_GROUP *group,
                                                       EC_POINT *r[], size_t num,
                                                       const unsigned char *strings[],
                                                       BN_CTX *ctx))
{
    meth->strings_to_points = func;
}

int (*EC_POINT_METHOD_get_strings_to_points_scalar_mul(EC_POINT_METHOD *meth))
    (const EC_GROUP *group, EC_POINT *r[], size_t num, const unsigned char *strings[],
     const BIGNUM *scalar, BN_CTX *ctx)
{
    return meth->strings_to_points_scalar_mul;
}

void EC_POINT_METHOD_set_strings_to_points_scalar_mul(EC_POINT_METHOD *meth,
                                                      int (*func)(const EC_GROUP *group,
                                                                  EC_POINT *r[], size_t num,
                                                                  const unsigned char *strings[],
                                                                  const BIGNUM *scalar,
                                                                  BN_CTX *ctx))
{
    meth->strings_to_points_scalar_mul = func;
}
