/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/zkperr.h>
#include <crypto/ec/ec_local.h>
#include "zkp_util.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)

static point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;

int zkp_str2point(const EC_GROUP *group, const unsigned char *str, size_t len,
                  EC_POINT *r, BN_CTX *bn_ctx)
{
    int ret = 0, i = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    unsigned char *p = (unsigned char *)str;
    BN_CTX *ctx = NULL;
    BIGNUM *x;

    memset(hash_res, 0, sizeof(hash_res));

    if (bn_ctx == NULL) {
        if ((ctx = bn_ctx = BN_CTX_new_ex(group->libctx)) == NULL)
            goto end;
    }

    BN_CTX_start(bn_ctx);
    if ((x = BN_CTX_get(bn_ctx)) == NULL)
        goto end;

    do {
        if (!SHA256(p, len, hash_res))
            goto end;

        BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, x);

        p  = &hash_res[0];
        len = sizeof(hash_res);

        if(EC_POINT_set_compressed_coordinates(group, r, x, 0, bn_ctx) == 1) {
            ret = 1;
            break;
        }

        ERR_clear_error();
    } while (i++ < 10);

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(ctx);
    return ret;
}

size_t zkp_point2oct(const EC_GROUP *group, const EC_POINT *P,
                     unsigned char *buf, BN_CTX *bn_ctx)
{
    size_t plen;
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;

    if (group == NULL || P == NULL || bn_ctx == NULL)
        return -1;

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                              format, NULL, 0, bn_ctx);
    if (plen <= 0 || buf == NULL)
        return plen;

    if (EC_POINT_point2oct(group, P, format, buf, plen, bn_ctx) <= 0)
        return -1;

    return plen;
}

int zkp_bin_hash2bn(const unsigned char *data, size_t len, BIGNUM *r)
{
    int ret = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];

    if (data == NULL || len <= 0 || r == NULL)
        return ret;

    if (!SHA256(data, len, hash_res))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, r))
        goto end;

    ret = 1;
end:
    return ret;
}

int zkp_next_power_of_two(int num)
{
    int next_power_of_2 = 1;

    while(next_power_of_2 < num) {
        next_power_of_2 <<= 1;
    }

    return next_power_of_2;
}

int zkp_floor_log2(int x)
{
    int result = 0;

    while (x > 1) {
        x >>= 1;
        result++;
    }

    return result;
}

int zkp_inner_product(BIGNUM *r, int num, const BIGNUM *a[], const BIGNUM *b[],
                      const BIGNUM *order, BN_CTX *bn_ctx)
{
    int ret = 0, i;
    BN_CTX *ctx = NULL;
    BIGNUM *v, *t;
    const BIGNUM *p;

    if (r == NULL || num <= 0 || (a == NULL && b == NULL))
        return 0;

    if (bn_ctx == NULL) {
        if ((ctx = bn_ctx = BN_CTX_new()) == NULL)
            goto end;
    }

    BN_CTX_start(bn_ctx);
    v = BN_CTX_get(bn_ctx);
    if ((t = BN_CTX_get(bn_ctx)) == NULL)
        goto end;

    BN_zero(v);

    for (i = 0; i < num; i++) {
        if (a == NULL) {
            p = b[i];
        } else if (b == NULL) {
            p = a[i];
        } else {
            if (!BN_mod_mul(t, a[i], b[i], order, bn_ctx))
                goto end;
            p = t;
        }

        if (!BN_mod_add(v, v, p, order, bn_ctx))
            goto end;
    }

    if (!BN_copy(r, v))
        goto end;

    ret = 1;

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(ctx);
    return ret;
}

zkp_poly_points_t *zkp_poly_points_new(int capacity)
{
    zkp_poly_points_t *ret = NULL;

    if (capacity <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(ret->points = OPENSSL_zalloc(sizeof(*ret->points) * capacity))
        || !(ret->scalars = OPENSSL_zalloc(sizeof(*ret->scalars) * capacity))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret->num = 0;
    ret->capacity = capacity;

    return ret;
err:
    zkp_poly_points_free(ret);
    return NULL;
}

void zkp_poly_points_free(zkp_poly_points_t *ps)
{
    if (ps == NULL)
        return;

    OPENSSL_free(ps->points);
    OPENSSL_free(ps->scalars);
    OPENSSL_free(ps);
}

void zkp_poly_points_reset(zkp_poly_points_t *ps)
{
    if (ps == NULL || ps->num == 0)
        return;

    memset(ps->points, 0, sizeof(*ps->points) * ps->num);
    memset(ps->scalars, 0, sizeof(*ps->scalars) * ps->num);
    ps->num = 0;
}

int zkp_poly_points_append(zkp_poly_points_t *ps, EC_POINT *point, BIGNUM *scalar)
{
    if (ps == NULL || point == NULL || scalar == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ps->num >= ps->capacity)
        return 0;

    ps->points[ps->num] = point;
    ps->scalars[ps->num] = scalar;
    ps->num++;

    return 1;
}

int zkp_poly_points_mul(zkp_poly_points_t *ps, EC_POINT *r, BIGNUM *scalar,
                        const EC_GROUP *group, BN_CTX *bn_ctx)
{
    if (ps == NULL || r == NULL || group == NULL || bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return EC_POINTs_mul(group, r, scalar, ps->num, (const EC_POINT **)ps->points,
                         (const BIGNUM **)ps->scalars, bn_ctx);
}

int zkp_bignum_encode(BIGNUM *bn, unsigned char *out, int bn_len)
{
    unsigned char *p = out;

    if (bn == NULL)
        return 0;

    *p++ = BN_is_negative(bn) ? '-' : '+';

    if (!BN_bn2binpad(bn, p, bn_len))
        goto end;

    p += bn_len;

end:
    return p - out;
}

BIGNUM *zkp_bignum_decode(const unsigned char *in, int *len, int bn_len)
{
    int neg;
    unsigned char *p = (unsigned char *)in;
    BIGNUM *b = NULL;

    if (in == NULL)
        return NULL;

    b = BN_new();
    if (b == NULL)
        return NULL;

    neg = *p++ == '-' ? 1 : 0;

    if (!BN_bin2bn(p, bn_len, b))
        goto err;

    BN_set_negative(b, neg);

    p += bn_len;

    if (len != NULL)
        *len = p - in;

    return b;
err:
    BN_free(b);
    return NULL;
}

int zkp_stack_of_bignum_encode(STACK_OF(BIGNUM) *sk, unsigned char *out,
                               int bn_len)
{
    int i, n, *q;
    unsigned char *p;
    BIGNUM *b;

    n = sk ? sk_BIGNUM_num(sk) : 0;
    if (out == NULL)
        return sizeof(n) + n * (bn_len + 1);

    q = (int *)out;
    *q++ = zkp_l2n((int)n);
    p = (unsigned char *)q;

    for (i = 0; i < n; i++) {
        b = sk_BIGNUM_value(sk, i);
        if (b == NULL)
            goto end;

        *p++ = BN_is_negative(b) ? '-' : '+';

        if (!BN_bn2binpad(b, p, bn_len))
            goto end;

        p += bn_len;
    }

end:
    return p - out;
}

STACK_OF(BIGNUM) *zkp_stack_of_bignum_decode(const unsigned char *in,
                                             int *len, int bn_len)
{
    unsigned char *p;
    int *q = (int *)in, n, i, neg;
    BIGNUM *b = NULL;
    STACK_OF(BIGNUM) *ret;

    n = (int)zkp_n2l(*q);
    q++;
    p = (unsigned char *)q;

    if (n < 0) {
        return NULL;
    }

    if (!(ret = sk_BIGNUM_new_reserve(NULL, n)))
        return NULL;

    for (i = 0; i < n; i++) {
        b = BN_new();
        if (b == NULL)
            goto err;

        neg = *p++ == '-' ? 1 : 0;

        if (!BN_bin2bn(p, (int)bn_len, b))
            goto err;

        BN_set_negative(b, neg);

        if (sk_BIGNUM_push(ret, b) <= 0)
            goto err;

        p += bn_len;
    }

    if (len != NULL)
        *len = p - in;

    return ret;
err:
    BN_free(b);
    sk_BIGNUM_pop_free(ret, BN_free);
    return NULL;
}

int zkp_stack_of_point_encode(STACK_OF(EC_POINT) *sk, unsigned char *out,
                              const EC_GROUP *group, BN_CTX *bn_ctx)
{
    int i, n, *q;
    size_t point_len;
    unsigned char *p;
    EC_POINT *P;

    if (sk == NULL || group == NULL)
        return 0;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    n = sk_EC_POINT_num(sk);
    if (out == NULL)
        return sizeof(n) + n * point_len;

    q = (int *)out;
    *q++ = zkp_l2n((int)n);
    p = (unsigned char *)q;

    for (i = 0; i < n; i++) {
        P = sk_EC_POINT_value(sk, i);
        if (P == NULL)
            goto end;

        if (EC_POINT_point2oct(group, P, form, p, point_len, bn_ctx) == 0)
            goto end;

        p += point_len;
    }

end:
    return p - out;
}

STACK_OF(EC_POINT) *zkp_stack_of_point_decode(const unsigned char *in, int *len,
                                              const EC_GROUP *group,
                                              BN_CTX *bn_ctx)
{
    unsigned char *p;
    int *q = (int *)in, n, i;
    size_t point_len;
    EC_POINT *P = NULL;
    STACK_OF(EC_POINT) *ret = NULL;

    if (in == NULL || group == NULL)
        return 0;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    n = (int)zkp_n2l(*q);
    q++;
    p = (unsigned char *)q;

    if (n < 0) {
        return NULL;
    }

    if (!(ret = sk_EC_POINT_new_reserve(NULL, n)))
        return NULL;

    for (i = 0; i < n; i++) {
        if (!(P = EC_POINT_new(group)))
            goto err;

        if (!EC_POINT_oct2point(group, P, p, point_len, bn_ctx))
            goto err;

        if (sk_EC_POINT_push(ret, P) <= 0)
            goto err;

        p += point_len;
    }

    if (len != NULL)
        *len = p - in;

    return ret;
err:
    EC_POINT_free(P);
    sk_EC_POINT_pop_free(ret, EC_POINT_free);
    return NULL;
}

