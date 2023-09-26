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

EC_POINT *zkp_random_ec_point_new(const EC_GROUP *group, BN_CTX *bn_ctx)
{
    BIGNUM *r = NULL;
    BN_CTX *bctx = NULL;
    EC_POINT *P = NULL;
    const BIGNUM *order;

    if (group == NULL)
        return NULL;

    if (bn_ctx == NULL) {
        bctx = bn_ctx = BN_CTX_new_ex(group->libctx);
        if (bn_ctx == NULL)
            goto err;
    }

    order = EC_GROUP_get0_order(group);

    BN_CTX_start(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    if (r == NULL)
        goto err;

    zkp_rand_range(r, order);

    if (!(P = EC_POINT_new(group)) || !EC_POINT_mul(group, P, r, NULL, NULL, bn_ctx))
        goto err;

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    return P;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    zkp_random_ec_point_free(P);
    return NULL;
}

void zkp_random_ec_point_free(EC_POINT *P)
{
    if (P == NULL)
        return;

    EC_POINT_free(P);
}

int zkp_random_bn_gen(const EC_GROUP *group, BIGNUM **r, size_t n, BN_CTX *bn_ctx)
{
    size_t i;
    const BIGNUM *order;

    if (group == NULL || r == NULL || bn_ctx == NULL)
        return 0;

    order = EC_GROUP_get0_order(group);

    for (i = 0; i < n; i++) {
        if (!(r[i] = BN_CTX_get(bn_ctx)) || !zkp_rand_range(r[i], order))
            return 0;
    }

    return 1;
}

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

int zkp_point2point(const EC_GROUP *group, const EC_POINT *P, EC_POINT *H, BN_CTX *bn_ctx)
{
    int ret = 0;
    size_t len;
    unsigned char *buf = NULL;
    BN_CTX *bctx = NULL;

    if (group == NULL || P == NULL || H == NULL)
        return -1;

    if (bn_ctx == NULL) {
        bctx = bn_ctx = BN_CTX_new();
    }

    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    len = EC_POINT_point2oct(group, P, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
    if (len <= 0)
        goto err;

    buf = OPENSSL_zalloc(len);
    if (buf == NULL)
        goto err;

    if (!EC_POINT_point2oct(group, P, POINT_CONVERSION_COMPRESSED, buf, len, bn_ctx))
        goto err;

    if (!EC_POINT_from_string(group, H, buf, len))
        goto err;

    ret = 1;
err:
    OPENSSL_free(buf);
    BN_CTX_free(bctx);
    return ret;
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

int zkp_is_power_of_two(int num)
{
    return (num != 0) && ((num & (num - 1)) == 0);
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

zkp_poly3_t *zkp_poly3_new(int n, const BIGNUM *order)
{
    int i;
    zkp_poly3_t *ret = NULL;

    if (n < 0 || order == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->order = order;

    if (!(ret->bn_ctx = BN_CTX_new()))
        goto err;

    if (n == 0) {
        ret->n = 0;
        return ret;
    }

    if (!(ret->x0 = OPENSSL_zalloc(sizeof(*ret->x0) * n))
        || !(ret->x1 = OPENSSL_zalloc(sizeof(*ret->x1) * n))
        || !(ret->x2 = OPENSSL_zalloc(sizeof(*ret->x2) * n))
        || !(ret->x3 = OPENSSL_zalloc(sizeof(*ret->x3) * n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret->n = n;

    for (i = 0; i < n; i++) {
        ret->x0[i] = BN_CTX_get(ret->bn_ctx);
        ret->x1[i] = BN_CTX_get(ret->bn_ctx);
        ret->x2[i] = BN_CTX_get(ret->bn_ctx);
        if (!(ret->x3[i] = BN_CTX_get(ret->bn_ctx)))
            goto err;

        BN_zero(ret->x0[i]);
        BN_zero(ret->x1[i]);
        BN_zero(ret->x2[i]);
        BN_zero(ret->x3[i]);
    }

    return ret;
err:
    zkp_poly3_free(ret);
    return NULL;
}

void zkp_poly3_free(zkp_poly3_t *poly3)
{
    if (poly3 == NULL)
        return;

    BN_CTX_free(poly3->bn_ctx);
    OPENSSL_free(poly3->x0);
    OPENSSL_free(poly3->x1);
    OPENSSL_free(poly3->x2);
    OPENSSL_free(poly3->x3);
    OPENSSL_free(poly3);
}

STACK_OF(BIGNUM) *zkp_poly3_eval(zkp_poly3_t *poly3, const BIGNUM *x)
{
    int i;
    BIGNUM *eval = NULL;
    STACK_OF(BIGNUM) *ret = NULL;

    if (poly3 == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!(ret = sk_BIGNUM_new_reserve(NULL, poly3->n)))
        return 0;

    for (i = 0; i < poly3->n; i++) {
        if (!(eval = BN_CTX_get(poly3->bn_ctx)))
            goto err;
        if (!BN_mod_mul(eval, x, poly3->x3[i], poly3->order, poly3->bn_ctx)
            || !BN_mod_add(eval, eval, poly3->x2[i], poly3->order, poly3->bn_ctx)
            || !BN_mod_mul(eval, eval, x, poly3->order, poly3->bn_ctx)
            || !BN_mod_add(eval, eval, poly3->x1[i], poly3->order, poly3->bn_ctx)
            || !BN_mod_mul(eval, eval, x, poly3->order, poly3->bn_ctx)
            || !BN_mod_add(eval, eval, poly3->x0[i], poly3->order, poly3->bn_ctx))
            goto err;

        if (sk_BIGNUM_push(ret, eval) <= 0)
            goto err;
    }

    return ret;
err:
    sk_BIGNUM_free(ret);
    return NULL;
}

int zkp_poly3_special_inner_product(zkp_poly6_t *r, zkp_poly3_t *lhs, zkp_poly3_t *rhs)
{
    int ret = 0;
    BIGNUM *t;

    if (r == NULL || lhs == NULL || rhs == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (lhs->n != rhs->n) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (lhs->n == 0) {
        BN_zero(r->t1);
        BN_zero(r->t2);
        BN_zero(r->t3);
        BN_zero(r->t4);
        BN_zero(r->t5);
        BN_zero(r->t6);
        return 1;
    }

    BN_CTX_start(r->bn_ctx);

    if (!(t = BN_CTX_get(r->bn_ctx)))
        goto err;

    if (!zkp_inner_product(r->t1, lhs->n, (const BIGNUM **)lhs->x1,
                          (const BIGNUM **)rhs->x0, r->order, r->bn_ctx)
        || !zkp_inner_product(r->t2, lhs->n, (const BIGNUM **)lhs->x1,
                             (const BIGNUM **)rhs->x1, r->order, r->bn_ctx)
        || !zkp_inner_product(t, lhs->n, (const BIGNUM **)lhs->x2,
                             (const BIGNUM **)rhs->x0, r->order, r->bn_ctx)
        || !BN_mod_add(r->t2, r->t2, t, r->order, r->bn_ctx)
        || !zkp_inner_product(r->t3, lhs->n, (const BIGNUM **)lhs->x2,
                             (const BIGNUM **)rhs->x1, r->order, r->bn_ctx)
        || !zkp_inner_product(t, lhs->n, (const BIGNUM **)lhs->x3,
                             (const BIGNUM **)rhs->x0, r->order, r->bn_ctx)
        || !BN_mod_add(r->t3, r->t3, t, r->order, r->bn_ctx)
        || !zkp_inner_product(r->t4, lhs->n, (const BIGNUM **)lhs->x1,
                             (const BIGNUM **)rhs->x3, r->order, r->bn_ctx)
        || !zkp_inner_product(t, lhs->n, (const BIGNUM **)lhs->x3,
                             (const BIGNUM **)rhs->x1, r->order, r->bn_ctx)
        || !BN_mod_add(r->t4, r->t4, t, r->order, r->bn_ctx)
        || !zkp_inner_product(r->t5, lhs->n, (const BIGNUM **)lhs->x2,
                             (const BIGNUM **)rhs->x3, r->order, r->bn_ctx)
        || !zkp_inner_product(r->t6, lhs->n, (const BIGNUM **)lhs->x3,
                             (const BIGNUM **)rhs->x3, r->order, r->bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_end(r->bn_ctx);
    return ret;
}

zkp_poly6_t *zkp_poly6_new(const BIGNUM *order)
{
    zkp_poly6_t *ret = NULL;

    if (order == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!(ret = OPENSSL_zalloc(sizeof(zkp_poly6_t)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(ret->bn_ctx = BN_CTX_new()))
        goto err;

    ret->t1 = BN_CTX_get(ret->bn_ctx);
    ret->t2 = BN_CTX_get(ret->bn_ctx);
    ret->t3 = BN_CTX_get(ret->bn_ctx);
    ret->t4 = BN_CTX_get(ret->bn_ctx);
    ret->t5 = BN_CTX_get(ret->bn_ctx);
    ret->t6 = BN_CTX_get(ret->bn_ctx);
    if (ret->t6 == NULL)
        goto err;

    ret->order = order;
    return ret;
err:
    zkp_poly6_free(ret);
    return NULL;
}

void zkp_poly6_free(zkp_poly6_t *poly6)
{
    if (poly6 == NULL)
        return;

    BN_CTX_free(poly6->bn_ctx);
    OPENSSL_free(poly6);
}

int zkp_poly6_eval(zkp_poly6_t *poly6, const BIGNUM *x, BIGNUM *r)
{
    int ret = 0;

    if (poly6 == NULL || r == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!BN_mod_mul(r, x, poly6->t6, poly6->order, poly6->bn_ctx)
        || !BN_mod_add(r, r, poly6->t5, poly6->order, poly6->bn_ctx)
        || !BN_mod_mul(r, r, x, poly6->order, poly6->bn_ctx)
        || !BN_mod_add(r, r, poly6->t4, poly6->order, poly6->bn_ctx)
        || !BN_mod_mul(r, r, x, poly6->order, poly6->bn_ctx)
        || !BN_mod_add(r, r, poly6->t3, poly6->order, poly6->bn_ctx)
        || !BN_mod_mul(r, r, x, poly6->order, poly6->bn_ctx)
        || !BN_mod_add(r, r, poly6->t2, poly6->order, poly6->bn_ctx)
        || !BN_mod_mul(r, r, x, poly6->order, poly6->bn_ctx)
        || !BN_mod_add(r, r, poly6->t1, poly6->order, poly6->bn_ctx)
        || !BN_mod_mul(r, r, x, poly6->order, poly6->bn_ctx))
        goto err;

    ret = 1;
err:
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

