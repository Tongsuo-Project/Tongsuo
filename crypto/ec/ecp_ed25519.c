/*
 * Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include <openssl/err.h>
#include "ec_local.h"

static int ec_GFp_ed25519_point_init(EC_POINT *point)
{
    point->X = BN_new();
    point->Y = BN_new();
    point->Z = BN_new();
    point->T = BN_new();
    point->Z_is_one = 0;

    if (point->X == NULL || point->Y == NULL || point->Z == NULL || point->T == NULL) {
        BN_free(point->X);
        BN_free(point->Y);
        BN_free(point->Z);
        BN_free(point->T);
        return 0;
    }
    return 1;
}

static void ec_GFp_ed25519_point_finish(EC_POINT *point)
{
    BN_free(point->X);
    BN_free(point->Y);
    BN_free(point->Z);
    BN_free(point->T);
}

static void ec_GFp_ed25519_point_clear_finish(EC_POINT *point)
{
    BN_clear_free(point->X);
    BN_clear_free(point->Y);
    BN_clear_free(point->Z);
    BN_clear_free(point->T);
    point->Z_is_one = 0;
}

static int ec_GFp_ed25519_point_copy(EC_POINT *dest, const EC_POINT *src)
{
    if (!BN_copy(dest->X, src->X))
        return 0;
    if (!BN_copy(dest->Y, src->Y))
        return 0;
    if (!BN_copy(dest->Z, src->Z))
        return 0;
    if (!BN_copy(dest->T, src->T))
        return 0;
    dest->Z_is_one = src->Z_is_one;
    dest->curve_name = src->curve_name;

    return 1;
}

static int ec_GFp_ed25519_point_set_to_infinity(const EC_GROUP *group,
                                                EC_POINT *point)
{
    point->Z_is_one = 1;
    BN_zero(point->X);
    BN_one(point->Y);
    BN_one(point->Z);
    BN_zero(point->T);
    return 1;
}

static int ec_GFp_ed25519_point_is_at_infinity(const EC_GROUP *group,
                                               const EC_POINT *point)
{
    return BN_is_zero(point->X) && BN_is_one(point->Y) &&
           BN_is_one(point->Z) && BN_is_zero(point->T);
}

static int ec_GFp_ed25519_group_init(EC_GROUP *group)
{
    group->field = BN_new();
    //group->a = BN_new();
    group->b = BN_new();
    group->order = BN_new();
    group->cofactor = BN_new();
    if (group->field == NULL || group->b == NULL || group->order == NULL
        || group->cofactor == NULL) {
        BN_free(group->field);
        //BN_free(group->a);
        BN_free(group->b);
        BN_free(group->order);
        BN_free(group->cofactor);
        return 0;
    }
    //group->a_is_minus3 = 0;
    return 1;
}

static void ec_GFp_ed25519_group_finish(EC_GROUP *group)
{
    BN_free(group->field);
    //BN_free(group->a);
    BN_free(group->b);
    BN_free(group->order);
    BN_free(group->cofactor);
    group->order = NULL;
    group->cofactor = NULL;
}

static void ec_GFp_ed25519_group_clear_finish(EC_GROUP *group)
{
    BN_clear_free(group->field);
    //BN_clear_free(group->a);
    BN_clear_free(group->b);
    BN_clear_free(group->order);
    BN_clear_free(group->cofactor);
    group->order = NULL;
    group->cofactor = NULL;
}

static int ec_GFp_ed25519_group_copy(EC_GROUP *dest, const EC_GROUP *src)
{
    if (!BN_copy(dest->field, src->field))
        return 0;
    /*
    if (!BN_copy(dest->a, src->a))
        return 0;
    */
    if (!BN_copy(dest->b, src->b))
        return 0;

    if (!BN_copy(dest->order, src->order))
        return 0;

    if (!BN_copy(dest->cofactor, src->cofactor))
        return 0;

    //dest->a_is_minus3 = src->a_is_minus3;

    return 1;
}

static int ec_GFp_ed25519_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                          const BIGNUM *a, const BIGNUM *b,
                                          BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX *new_ctx = NULL;
    BIGNUM *tmp_b;

    /* p must be a prime >= 5 */
    if (BN_num_bits(p) < 5 || !BN_is_odd(p)) {
        return 0;
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    BN_CTX_start(ctx);
    tmp_b = BN_CTX_get(ctx);
    if (tmp_b == NULL)
        goto err;

    /* group->field */
    if (!BN_copy(group->field, p))
        goto err;
    BN_set_negative(group->field, 0);

    /* ignore group->a */

    /* group->b is used to save parameter d of the edwards curve */
    if (!BN_nnmod(tmp_b, b, p, ctx))
        goto err;
    if (group->meth->field_encode) {
        if (!group->meth->field_encode(group, group->b, tmp_b, ctx))
            goto err;
    } else if (!BN_copy(group->b, tmp_b))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ec_GFp_ed25519_group_get_curve(const EC_GROUP *group, BIGNUM *p,
                                          BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
{
    if (p != NULL) {
        if (!BN_copy(p, group->field))
            return 0;
    }

    return 1;
}

static int ec_GFp_ed25519_group_check_discriminant(const EC_GROUP *group,
                                                   BN_CTX *ctx)
{
    /* TODO */
    return 1;
}

static int ec_GFp_ed25519_point_set_affine_coordinates(const EC_GROUP *group,
                                                       EC_POINT *point,
                                                       const BIGNUM *x,
                                                       const BIGNUM *y,
                                                       BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    const BIGNUM *z = BN_value_one();
    int ret = 0, Z_is_one;

    if (x == NULL || y == NULL) {
        /*
         * unlike for projective coordinates, we do not tolerate this
         */
        ECerr(EC_F_EC_GFP_ED25519_POINT_SET_AFFINE_COORDINATES,
              ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    if (x != NULL) {
        if (!BN_nnmod(point->X, x, group->field, ctx))
            goto err;
        if (group->meth->field_encode) {
            if (!group->meth->field_encode(group, point->X, point->X, ctx))
                goto err;
        }
    }

    if (y != NULL) {
        if (!BN_nnmod(point->Y, y, group->field, ctx))
            goto err;
        if (group->meth->field_encode) {
            if (!group->meth->field_encode(group, point->Y, point->Y, ctx))
                goto err;
        }
    }

    if (!BN_nnmod(point->Z, z, group->field, ctx))
        goto err;
    Z_is_one = BN_is_one(point->Z);
    if (group->meth->field_encode) {
        if (Z_is_one && (group->meth->field_set_to_one != 0)) {
            if (!group->meth->field_set_to_one(group, point->Z, ctx))
                goto err;
        } else {
            if (!group->
                meth->field_encode(group, point->Z, point->Z, ctx))
                goto err;
        }
    }
    point->Z_is_one = Z_is_one;

    if (Z_is_one) {
        if (!group->meth->field_mul(group, point->T, point->X, point->Y, ctx))
            goto err;
    } else {
        //TODO
    }

    ret = 1;

 err:
    BN_CTX_free(new_ctx);
    return ret;
}

static int ec_GFp_ed25519_point_get_affine_coordinates(const EC_GROUP *group,
                                                       const EC_POINT *point,
                                                       BIGNUM *x, BIGNUM *y,
                                                       BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BIGNUM *Z, *Z_1;
    const BIGNUM *Z_;
    int ret = 0;

    if (EC_POINT_is_at_infinity(group, point)) {
        return 0;
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    BN_CTX_start(ctx);
    Z = BN_CTX_get(ctx);
    Z_1 = BN_CTX_get(ctx);
    if (Z_1 == NULL)
        goto err;

    /* transform  (X, Y, Z)  into  (x, y) := (X/Z, Y/Z) */

    if (group->meth->field_decode) {
        if (!group->meth->field_decode(group, Z, point->Z, ctx))
            goto err;
        Z_ = Z;
    } else {
        Z_ = point->Z;
    }

    if (BN_is_one(Z_)) {
        if (group->meth->field_decode) {
            if (x != NULL) {
                if (!group->meth->field_decode(group, x, point->X, ctx))
                    goto err;
            }
            if (y != NULL) {
                if (!group->meth->field_decode(group, y, point->Y, ctx))
                    goto err;
            }
        } else {
            if (x != NULL) {
                if (!BN_copy(x, point->X))
                    goto err;
            }
            if (y != NULL) {
                if (!BN_copy(y, point->Y))
                    goto err;
            }
        }
    } else {
        if (!group->meth->field_inv(group, Z_1, Z_, ctx)) {
            goto err;
        }

        if (x != NULL) {
            /*
             * in the Montgomery case, field_mul will cancel out Montgomery
             * factor in X:
             */
            if (!group->meth->field_mul(group, x, point->X, Z_1, ctx))
                goto err;
        }

        if (y != NULL) {
            /*
             * in the Montgomery case, field_mul will cancel out Montgomery
             * factor in Y:
             */
            if (!group->meth->field_mul(group, y, point->Y, Z_1, ctx))
                goto err;
        }
    }

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ec_GFp_ed25519_point_set_compressed_coordinates(const EC_GROUP *group,
                                                           EC_POINT *point,
                                                           const BIGNUM *x,
                                                           int y_bit,
                                                           BN_CTX *ctx)
{
    /* TODO */
    return 1;
}

static size_t ec_GFp_ed25519_point2oct(const EC_GROUP *group,
                                       const EC_POINT *point,
                                       point_conversion_form_t form,
                                       unsigned char *buf, size_t len,
                                       BN_CTX *ctx)
{
    size_t ret;
    BN_CTX *new_ctx = NULL;
    int used_ctx = 0;
    BIGNUM *x, *y;
    size_t field_len, i, skip;

    form = POINT_CONVERSION_UNCOMPRESSED;

    if ((form != POINT_CONVERSION_COMPRESSED)
        && (form != POINT_CONVERSION_UNCOMPRESSED)
        && (form != POINT_CONVERSION_HYBRID)) {
        ECerr(EC_F_EC_GFP_ED25519_POINT2OCT, EC_R_INVALID_FORM);
        goto err;
    }

    if (EC_POINT_is_at_infinity(group, point)) {
        /* encodes to a single 0 octet */
        if (buf != NULL) {
            if (len < 1) {
                ECerr(EC_F_EC_GFP_ED25519_POINT2OCT, EC_R_BUFFER_TOO_SMALL);
                return 0;
            }
            buf[0] = 0;
        }
        return 1;
    }

    /* ret := required output buffer length */
    field_len = BN_num_bytes(group->field);
    ret =
        (form ==
         POINT_CONVERSION_COMPRESSED) ? 1 + field_len : 1 + 2 * field_len;

    /* if 'buf' is NULL, just return required length */
    if (buf != NULL) {
        if (len < ret) {
            ECerr(EC_F_EC_GFP_ED25519_POINT2OCT, EC_R_BUFFER_TOO_SMALL);
            goto err;
        }

        if (ctx == NULL) {
            ctx = new_ctx = BN_CTX_new();
            if (ctx == NULL)
                return 0;
        }

        BN_CTX_start(ctx);
        used_ctx = 1;
        x = BN_CTX_get(ctx);
        y = BN_CTX_get(ctx);
        if (y == NULL)
            goto err;

        if (!EC_POINT_get_affine_coordinates(group, point, x, y, ctx))
            goto err;

        if ((form == POINT_CONVERSION_COMPRESSED
             || form == POINT_CONVERSION_HYBRID) && BN_is_odd(y))
            buf[0] = form + 1;
        else
            buf[0] = form;

        i = 1;

        skip = field_len - BN_num_bytes(x);
        if (skip > field_len) {
            ECerr(EC_F_EC_GFP_ED25519_POINT2OCT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        while (skip > 0) {
            buf[i++] = 0;
            skip--;
        }
        skip = BN_bn2bin(x, buf + i);
        i += skip;
        if (i != 1 + field_len) {
            ECerr(EC_F_EC_GFP_ED25519_POINT2OCT, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (form == POINT_CONVERSION_UNCOMPRESSED
            || form == POINT_CONVERSION_HYBRID) {
            skip = field_len - BN_num_bytes(y);
            if (skip > field_len) {
                ECerr(EC_F_EC_GFP_ED25519_POINT2OCT, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            while (skip > 0) {
                buf[i++] = 0;
                skip--;
            }
            skip = BN_bn2bin(y, buf + i);
            i += skip;
        }

        if (i != ret) {
            ECerr(EC_F_EC_GFP_ED25519_POINT2OCT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (used_ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;

 err:
    if (used_ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return 0;
}

static int ec_GFp_ed25519_oct2point(const EC_GROUP *group,
                                    EC_POINT *point, const unsigned char *buf,
                                    size_t len, BN_CTX *ctx)
{
    return ec_GFp_simple_oct2point(group, point, buf, len, ctx);
}

static int ec_GFp_ed25519_point_add(const EC_GROUP *group, EC_POINT *r,
                                    const EC_POINT *a, const EC_POINT *b,
                                    BN_CTX *ctx)
{
    int (*field_mul) (const EC_GROUP *, BIGNUM *, const BIGNUM *,
                      const BIGNUM *, BN_CTX *);
    const BIGNUM *p;
    BN_CTX *new_ctx = NULL;
    BIGNUM *n1, *n2, *n3, *n4, *n5, *n6;
    int ret = 0;

    if (a == b)
        return EC_POINT_dbl(group, r, a, ctx);
    if (EC_POINT_is_at_infinity(group, a))
        return EC_POINT_copy(r, b);
    if (EC_POINT_is_at_infinity(group, b))
        return EC_POINT_copy(r, a);

    field_mul = group->meth->field_mul;
    p = group->field;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    BN_CTX_start(ctx);
    n1 = BN_CTX_get(ctx);
    n2 = BN_CTX_get(ctx);
    n3 = BN_CTX_get(ctx);
    n4 = BN_CTX_get(ctx);
    n5 = BN_CTX_get(ctx);
    n6 = BN_CTX_get(ctx);
    if (n6 == NULL)
        goto end;

    /* n1 = Ya - Xa */
    if (!BN_mod_sub_quick(n1, a->Y, a->X, p))
        goto end;

    /* n2 = Yb - Xb */
    if (!BN_mod_sub_quick(n2, b->Y, b->X, p))
        goto end;

    /* n1 = n1 * n2 */
    if (!field_mul(group, n1, n1, n2, ctx))
        goto end;

    /* n3 = Ya + Xa */
    if (!BN_mod_add_quick(n3, a->Y, a->X, p))
        goto end;

    /* n4 = Yb + Xb */
    if (!BN_mod_add_quick(n4, b->Y, b->X, p))
        goto end;

    /* n2 = n3 * n4 */
    if (!field_mul(group, n2, n3, n4, ctx))
        goto end;

    /* n3 = Ta * 2 * d * Tb */
    if (!BN_lshift1(n3, a->T))
        goto end;
    if (!field_mul(group, n3, n3, group->b, ctx))
        goto end;
    if (!field_mul(group, n3, n3, b->T, ctx))
        goto end;

     /* n4 = Za * 2 * Zb */
    if (!BN_lshift1(n4, a->Z))
        goto end;
    if (!field_mul(group, n4, n4, b->Z, ctx))
        goto end;

    /* n5 = n2 - n1 */
    if (!BN_mod_sub_quick(n5, n2, n1, p))
        goto end;

    /* n6 = n2 + n1 */
    if (!BN_mod_add_quick(n6, n2, n1, p))
        goto end;

    /* n1 = n4 - n3 */
    if (!BN_mod_sub_quick(n1, n4, n3, p))
        goto end;

    /* n2 = n4 + n3 */
    if (!BN_mod_add_quick(n2, n4, n3, p))
        goto end;

    /* Xr = n5 * n1 */
    if (!field_mul(group, r->X, n5, n1, ctx))
        goto end;

    /* Yr = n6 * n2 */
    if (!field_mul(group, r->Y, n6, n2, ctx))
        goto end;

    /* Zr = n1 * n2 */
    if (!field_mul(group, r->Z, n1, n2, ctx))
        goto end;
    r->Z_is_one = BN_is_one(r->Z);

    /* Tr = n5 * n6 */
    if (!field_mul(group, r->T, n5, n6, ctx))
        goto end;

    ret = 1;

 end:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ec_GFp_ed25519_point_dbl(const EC_GROUP *group, EC_POINT *r,
                                    const EC_POINT *a, BN_CTX *ctx)
{
    int (*field_mul) (const EC_GROUP *, BIGNUM *, const BIGNUM *,
                      const BIGNUM *, BN_CTX *);
    int (*field_sqr) (const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
    const BIGNUM *p;
    BN_CTX *new_ctx = NULL;
    BIGNUM *n1, *n2, *n3, *n4, *n5, *n6;
    int ret = 0;

    if (EC_POINT_is_at_infinity(group, a))
        return ec_GFp_ed25519_point_set_to_infinity(group, r);

    field_mul = group->meth->field_mul;
    field_sqr = group->meth->field_sqr;
    p = group->field;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    BN_CTX_start(ctx);
    n1 = BN_CTX_get(ctx);
    n2 = BN_CTX_get(ctx);
    n3 = BN_CTX_get(ctx);
    n4 = BN_CTX_get(ctx);
    n5 = BN_CTX_get(ctx);
    n6 = BN_CTX_get(ctx);
    if (n6 == NULL)
        goto err;

    /* n1 = Xa ^ 2 */
    if (!field_sqr(group, n1, a->X, ctx))
        goto err;

    /* n2 = Ya ^ 2 */
    if (!field_sqr(group, n2, a->Y, ctx))
        goto err;

    /* n3 = 2 * Za ^ 2 */
    if (!field_sqr(group, n3, a->Z, ctx))
        goto err;
    if (!BN_lshift1(n3, n3))
        goto err;

    /* n4 = (Xa + Ya) ^ 2 */
    if (!BN_mod_add_quick(n4, a->X, a->Y, p))
        goto err;
    if (!field_sqr(group, n4, n4, ctx))
        goto err;

    /* n4 = n4 - n1 - n2 */
    if (!BN_mod_sub_quick(n4, n4, n1, p))
        goto err;
    if (!BN_mod_sub_quick(n4, n4, n2, p))
        goto err;

    /* n5 = n2 - n1 */
    if (!BN_mod_sub_quick(n5, n2, n1, p))
        goto err;

    /* n6 = n5 - n3 */
    if (!BN_mod_sub_quick(n6, n5, n3, p))
        goto err;

    /* n3 = -n1 - n2 */
    BN_set_negative(n1, 1);
    if (!BN_mod_sub_quick(n3, n1, n2, p))
        goto err;

    /* Xr = n4 * n6 */
    if (!field_mul(group, r->X, n4, n6, ctx))
        goto err;

    /* Yr = n5 * n3 */
    if (!field_mul(group, r->Y, n5, n3, ctx))
        goto err;

    /* Zr = n6 * n5 */
    if (!field_mul(group, r->Z, n6, n5, ctx))
        goto err;
    r->Z_is_one = BN_is_one(r->Z);

    /* Tr = n4 * n3 */
    if (!field_mul(group, r->T, n4, n3, ctx))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ec_GFp_ed25519_point_mul(const EC_GROUP *group, EC_POINT *r,
                                    const BIGNUM *scalar, const EC_POINT *point,
                                    BN_CTX *ctx)
{
    int ret = 0, i, bits;
    EC_POINT *p = NULL;

    if (group->meth->add == NULL || group->meth->dbl == NULL)
        return 0;

    if (!EC_POINT_set_to_infinity(group, r))
        goto err;

    if ((p = EC_POINT_new(group)) == NULL)
        return 0;

    if (!EC_POINT_copy(p, point))
        goto err;

    bits = BN_num_bits(scalar);

    for (i = 0;  i < bits; i++) {
        if (BN_is_bit_set(scalar, i)) {
            if (!group->meth->add(group, r, r, p, ctx))
                goto err;
        }

        if (!group->meth->dbl(group, p, p, ctx))
            goto err;
    }

    ret = 1;

 err:
    EC_POINT_free(p);
    return ret;
}

static int ec_GFp_ed25519_point_invert(const EC_GROUP *group, EC_POINT *point,
                                       BN_CTX *ctx)
{
    if (EC_POINT_is_at_infinity(group, point) || BN_is_zero(point->Y))
        /* point is its own inverse */
        return 1;

    if (!BN_usub(point->X, group->field, point->X))
        return 0;

    return BN_usub(point->T, group->field, point->T);
}

static int ec_GFp_ed25519_points_mul(const EC_GROUP *group, EC_POINT *r,
                                     const BIGNUM *scalar, size_t num,
                                     const EC_POINT *points[],
                                     const BIGNUM *scalars[], BN_CTX *ctx)
{
    int ret = 0;
    EC_POINT *p = NULL;

    //if (num != 1 || group->meth->add == NULL || group->meth->dbl == NULL)
    if (group->meth->add == NULL || group->meth->dbl == NULL)
        return 0;

    if (scalar != NULL) {
        if (!ec_GFp_ed25519_point_mul(group, r, scalar, group->generator, ctx))
            goto end;
    }

    if (num == 0) {
        ret = 1;
        goto end;
    } else if (num == 1){
        if ((p = EC_POINT_new(group)) == NULL)
            goto end;

        if (!ec_GFp_ed25519_point_mul(group, p, scalars[0], points[0], ctx))
            goto end;

        if (scalar != NULL) {
            if (!group->meth->add(group, r, r, p, ctx))
                goto end;
        } else {
            if (!EC_POINT_copy(r, p))
                goto end;
        }

        ret = 1;
    }

 end:
    EC_POINT_free(p);
    return ret;
}

static int ec_GFp_ed25519_point_is_on_curve(const EC_GROUP *group,
                                            const EC_POINT *point, BN_CTX *ctx)
{
    /* TODO */
    return 1;
}

static int ec_GFp_ed25519_point_cmp(const EC_GROUP *group, const EC_POINT *a,
                                    const EC_POINT *b, BN_CTX *ctx)
{
    /*-
     * return values:
     *  -1   error
     *   0   equal (in affine coordinates)
     *   1   not equal
     */

    int (*field_mul) (const EC_GROUP *, BIGNUM *, const BIGNUM *,
                      const BIGNUM *, BN_CTX *);
    BN_CTX *new_ctx = NULL;
    BIGNUM *tmp1, *tmp2;
    const BIGNUM *tmp1_, *tmp2_;
    int ret = -1;

    if (EC_POINT_is_at_infinity(group, a)) {
        return EC_POINT_is_at_infinity(group, b) ? 0 : 1;
    }

    if (EC_POINT_is_at_infinity(group, b))
        return 1;

    if (a->Z_is_one && b->Z_is_one) {
        return ((BN_cmp(a->X, b->X) == 0) && BN_cmp(a->Y, b->Y) == 0) ? 0 : 1;
    }

    field_mul = group->meth->field_mul;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return -1;
    }

    BN_CTX_start(ctx);
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);
    if (tmp2 == NULL)
        goto end;

    /*-
     * We have to decide whether
     *     (X_a/Z_a, Y_a/Z_a) = (X_b/Z_b, Y_b/Z_b),
     * or equivalently, whether
     *     (X_a*Z_b, Y_a*Z_b) = (X_b*Z_a, Y_b*Z_a).
     */

    if (!b->Z_is_one) {
        if (!field_mul(group, tmp1, a->X, b->Z, ctx))
            goto end;
        tmp1_ = tmp1;
    } else
        tmp1_ = a->X;
    if (!a->Z_is_one) {
        if (!field_mul(group, tmp2, b->X, a->Z, ctx))
            goto end;
        tmp2_ = tmp2;
    } else
        tmp2_ = b->X;

    /* compare  X_a*Z_b  with  X_b*Z_a */
    if (BN_cmp(tmp1_, tmp2_) != 0) {
        ret = 1;                /* points differ */
        goto end;
    }

    if (!b->Z_is_one) {
        if (!field_mul(group, tmp1, a->Y, b->Z, ctx))
            goto end;
        tmp1_ = tmp1;
    } else
        tmp1_ = a->Y;
    if (!a->Z_is_one) {
        if (!field_mul(group, tmp2, b->Y, a->Z, ctx))
            goto end;
        tmp2_ = tmp2;
    } else
        tmp2_ = b->Y;

    /* compare  Y_a*Z_b  with  Y_b*Z_a */
    if (BN_cmp(tmp1_, tmp2_) != 0) {
        ret = 1;                /* points differ */
        goto end;
    }

    /* points are equal */
    ret = 0;

 end:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

/* r = pow(a, 2^q, p) */
static int ec_GFp_ed25519_field_pow2(const EC_GROUP *group, BIGNUM *r,
                                     const BIGNUM *a, int q, BN_CTX *ctx)
{
    if (!BN_copy(r, a))
        return 0;

    while (q > 0) {
        if (!group->meth->field_sqr(group, r, r, ctx))
            return 0;
        q--;
    }

    return 1;
}

static int ec_GFp_ed25519_field_inv(const EC_GROUP *group, BIGNUM *r,
                                    const BIGNUM *a, BN_CTX *ctx)
{
    int (*field_mul) (const EC_GROUP *, BIGNUM *, const BIGNUM *,
                      const BIGNUM *, BN_CTX *);
    int (*field_sqr) (const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
    BIGNUM *n1, *n2, *n3, *n4;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_secure_new()) == NULL)
        return 0;

    field_mul = group->meth->field_mul;
    field_sqr = group->meth->field_sqr;

    BN_CTX_start(ctx);
    n1 = BN_CTX_get(ctx);
    n2 = BN_CTX_get(ctx);
    n3 = BN_CTX_get(ctx);
    n4 = BN_CTX_get(ctx);
    if (n4 == NULL)
        goto err;

     /* z2: n1 = a ^ 2 */
    if (!field_sqr(group, n1, a, ctx))
        goto err;

    /* z9: n2 = pow2(n1, 2) * a */
    if (!ec_GFp_ed25519_field_pow2(group, n2, n1, 2, ctx))
        goto err;
    if (!field_mul(group, n2, n2, a, ctx))
        goto err;

    /* z11: n3 = n2 * n1 */
    if (!field_mul(group, n3, n2, n1, ctx))
        goto err;

    /* z2_5_0: n4 = n3 ^ 2 * n2 */
    if (!field_sqr(group, n4, n3, ctx))
        goto err;
    if (!field_mul(group, n4, n4, n2, ctx))
        goto err;

    /* z2_10_0: n1 = pow2(n4, 5) * n4 */
    if (!ec_GFp_ed25519_field_pow2(group, n1, n4, 5, ctx))
        goto err;
    if (!field_mul(group, n1, n1, n4, ctx))
        goto err;

    /* z2_20_0: n2 = pow2(n1, 10) * n1 */
    if (!ec_GFp_ed25519_field_pow2(group, n2, n1, 10, ctx))
        goto err;
    if (!field_mul(group, n2, n2, n1, ctx))
        goto err;

    /* z2_40_0: n4 = pow2(n2, 20) * n2 */
    if (!ec_GFp_ed25519_field_pow2(group, n4, n2, 20, ctx))
        goto err;
    if (!field_mul(group, n4, n4, n2, ctx))
        goto err;

    /* z2_50_0: n2 = pow2(n4, 10) * n1 */
    if (!ec_GFp_ed25519_field_pow2(group, n2, n4, 10, ctx))
        goto err;
    if (!field_mul(group, n2, n2, n1, ctx))
        goto err;

    /* z2_100_0: n4 = pow2(n2, 10) * n2 */
    if (!ec_GFp_ed25519_field_pow2(group, n4, n2, 50, ctx))
        goto err;
    if (!field_mul(group, n4, n4, n2, ctx))
        goto err;

    /* z2_200_0: n1 = pow2(n4, 100) * n4 */
    if (!ec_GFp_ed25519_field_pow2(group, n1, n4, 100, ctx))
        goto err;
    if (!field_mul(group, n1, n1, n4, ctx))
        goto err;

    /* z2_250_0: n4 = pow2(n1, 100) * n2 */
    if (!ec_GFp_ed25519_field_pow2(group, n4, n1, 50, ctx))
        goto err;
    if (!field_mul(group, n4, n4, n2, ctx))
        goto err;

    /* r = pow2(n4, 5) * n3 */
    if (!ec_GFp_ed25519_field_pow2(group, r, n4, 5, ctx))
        goto err;
    if (!field_mul(group, r, r, n3, ctx))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

const EC_METHOD *EC_GFp_ed25519_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_CUSTOM_CURVE,
        NID_ED25519,
        ec_GFp_ed25519_group_init,
        ec_GFp_ed25519_group_finish,
        ec_GFp_ed25519_group_clear_finish,
        ec_GFp_ed25519_group_copy,
        ec_GFp_ed25519_group_set_curve,
        ec_GFp_ed25519_group_get_curve,
        ec_GFp_simple_group_get_degree,
        ec_group_simple_order_bits,
        ec_GFp_ed25519_group_check_discriminant,
        ec_GFp_ed25519_point_init,
        ec_GFp_ed25519_point_finish,
        ec_GFp_ed25519_point_clear_finish,
        ec_GFp_ed25519_point_copy,
        ec_GFp_ed25519_point_set_to_infinity,
        0, /* point_set_Jprojective_coordinates_GFp */
        0, /* point_get_Jprojective_coordinates_GFp */
        ec_GFp_ed25519_point_set_affine_coordinates,
        ec_GFp_ed25519_point_get_affine_coordinates,
        ec_GFp_ed25519_point_set_compressed_coordinates,
        ec_GFp_ed25519_point2oct,
        ec_GFp_ed25519_oct2point,
        ec_GFp_ed25519_point_add,
        ec_GFp_ed25519_point_dbl,
        ec_GFp_ed25519_point_invert,
        ec_GFp_ed25519_point_is_at_infinity,
        ec_GFp_ed25519_point_is_on_curve,
        ec_GFp_ed25519_point_cmp,
        ec_GFp_simple_make_affine,
        0, /* points_make_affine */
        ec_GFp_ed25519_points_mul,
        0, /* precompute_mult */
        0, /* have_precompute_mult */
        ec_GFp_simple_field_mul,
        ec_GFp_simple_field_sqr,
        0, /* field_div */
        ec_GFp_ed25519_field_inv,
        0, /* field_encode */
        0, /* field_decode */
        0, /* field_set_to_one */
        ec_key_simple_priv2oct,
        ec_key_simple_oct2priv,
        0, /* set private */
        ec_key_simple_generate_key,
        ec_key_simple_check_key,
        ec_key_simple_generate_public_key,
        0, /* keycopy */
        0, /* keyfinish */
        ecdh_simple_compute_key,
        0, /* field_inverse_mod_ord */
        0, /* blind_coordinates */
        0, /* ladder_pre */
        0, /* ladder_step */
        0 /* ladder_post */
    };

    return &ret;
}
