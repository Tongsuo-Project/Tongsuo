/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <crypto/ec.h>
#include <crypto/ec/ec_local.h>
#include "r1cs.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(BP_R1CS_VARIABLE)
DEFINE_STACK_OF(BP_R1CS_LINEAR_COMBINATION_ITEM)
DEFINE_STACK_OF(BP_R1CS_LINEAR_COMBINATION)

BP_R1CS_VARIABLE *BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_TYPE type, uint64_t value)
{
    BP_R1CS_VARIABLE *var = NULL;

    var = OPENSSL_zalloc(sizeof(*var));
    if (var == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    var->references = 1;
    if ((var->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    var->type = type;
    var->value = value;

    return var;
err:
    OPENSSL_free(var);
    return NULL;
}

BP_R1CS_VARIABLE *BP_R1CS_VARIABLE_dup(const BP_R1CS_VARIABLE *var)
{
    BP_R1CS_VARIABLE *ret;

    if (var == NULL)
        return NULL;

    if ((ret = BP_R1CS_VARIABLE_new(var->type, var->value)) == NULL)
        return NULL;

    return ret;
}

void BP_R1CS_VARIABLE_free(BP_R1CS_VARIABLE *var)
{
    int ref;

    if (var == NULL)
        return;

    CRYPTO_DOWN_REF(&var->references, &ref, var->lock);
    REF_PRINT_COUNT("BP_R1CS_VARIABLE", var);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    CRYPTO_THREAD_lock_free(var->lock);
    OPENSSL_clear_free((void *)var, sizeof(*var));
}

BP_R1CS_LC_ITEM *BP_R1CS_LC_ITEM_new(BP_R1CS_VARIABLE *var, const BIGNUM *scalar)
{
    int ref;
    BP_R1CS_LC_ITEM *item = NULL;
    BP_R1CS_VARIABLE *v = NULL;
    BIGNUM *s = NULL;

    item = OPENSSL_zalloc(sizeof(*item));
    if (item == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (var == NULL) {
        if (!(v = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_ONE, 1))) {
            goto err;
        }
        var = v;
    } else {
        if (CRYPTO_UP_REF(&var->references, &ref, var->lock) <= 0)
            goto err;
    }

    if (scalar == NULL) {
        if ((s = BN_new()) == NULL)
            goto err;

        BN_one(s);
    } else {
        if ((s = BN_dup(scalar)) == NULL)
            goto err;
    }

    item->variable = var;
    item->scalar = s;

    return item;
err:
    BN_free(s);
    BP_R1CS_VARIABLE_free(v);
    BP_R1CS_LC_ITEM_free(item);
    return NULL;
}

BP_R1CS_LC_ITEM *BP_R1CS_LC_ITEM_dup(BP_R1CS_LC_ITEM *item)
{
    if (item == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return BP_R1CS_LC_ITEM_new(item->variable, item->scalar);
}

void BP_R1CS_LC_ITEM_free(BP_R1CS_LC_ITEM *item)
{
    if (item == NULL)
        return;

    BP_R1CS_VARIABLE_free(item->variable);
    BN_free(item->scalar);
    OPENSSL_clear_free((void *)item, sizeof(*item));
}

BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_new(void)
{
    BP_R1CS_LINEAR_COMBINATION *lc = NULL;

    lc = OPENSSL_zalloc(sizeof(*lc));
    if (lc == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((lc->items = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_new_null()) == NULL)
        goto err;

    lc->references = 1;
    if ((lc->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    lc->type = BP_R1CS_LC_TYPE_UNKOWN;

    return lc;
err:
    BP_R1CS_LINEAR_COMBINATION_free(lc);
    return NULL;
}

BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_new_from_param(BP_R1CS_VARIABLE *var,
                                                                      const BIGNUM *scalar)
{
    BP_R1CS_LINEAR_COMBINATION *lc = NULL;
    BP_R1CS_LC_ITEM *item = NULL;

    lc = BP_R1CS_LINEAR_COMBINATION_new();
    if (lc == NULL) {
        return NULL;
    }

    if ((item = BP_R1CS_LC_ITEM_new(var, scalar)) == NULL
        || sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(lc->items, item) <= 0)
        goto err;

    return lc;
err:
    BP_R1CS_LINEAR_COMBINATION_free(lc);
    return NULL;
}

BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_dup(const BP_R1CS_LINEAR_COMBINATION *lc)
{
    int i, num;
    BP_R1CS_LINEAR_COMBINATION *ret = NULL;
    BP_R1CS_LC_ITEM *item, *item_dup = NULL;

    if (lc == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = BP_R1CS_LINEAR_COMBINATION_new();
    if (ret == NULL) {
        return NULL;
    }

    num  = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_num(lc->items);
    for (i = 0; i < num; i++) {
        item = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_value(lc->items, i);
        if (item == NULL)
            goto err;

        item_dup = BP_R1CS_LC_ITEM_dup(item);
        if (item_dup == NULL)
            goto err;

        sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(ret->items, item_dup);
    }

    ret->type = lc->type;

    return ret;

err:
    BP_R1CS_LINEAR_COMBINATION_free(ret);
    return NULL;
}

void BP_R1CS_LINEAR_COMBINATION_free(BP_R1CS_LINEAR_COMBINATION *lc)
{
    int ref;

    if (lc == NULL)
        return;

    CRYPTO_DOWN_REF(&lc->references, &ref, lc->lock);
    REF_PRINT_COUNT("BP_R1CS_LINEAR_COMBINATION", lc);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    CRYPTO_THREAD_lock_free(lc->lock);
    sk_BP_R1CS_LINEAR_COMBINATION_ITEM_pop_free(lc->items, BP_R1CS_LC_ITEM_free);
    OPENSSL_clear_free((void *)lc, sizeof(*lc));
}

int BP_R1CS_LINEAR_COMBINATION_clean(BP_R1CS_LINEAR_COMBINATION *lc)
{
    if (lc == NULL)
        return 0;

    sk_BP_R1CS_LINEAR_COMBINATION_ITEM_pop_free(lc->items, BP_R1CS_LC_ITEM_free);
    if ((lc->items = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_new_null()) == NULL)
        return 0;

    lc->type = BP_R1CS_LC_TYPE_UNKOWN;
    return 1;
}

static int BP_R1CS_LINEAR_COMBINATION_eval(BP_R1CS_CTX *ctx,
                                           const BP_R1CS_LINEAR_COMBINATION *lc,
                                           BIGNUM *r, BN_CTX *bn_ctx)
{
    int i, num, ret = 0;
    BN_CTX *bctx = NULL;
    BIGNUM *a, *product, *sum, *one;
    BP_WITNESS *witness;
    BP_R1CS_VARIABLE *var;
    BP_R1CS_LINEAR_COMBINATION_ITEM *item;

    if (ctx == NULL || ctx->witness == NULL || lc == NULL || r == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    witness = ctx->witness;

    if (bn_ctx == NULL) {
        bctx = bn_ctx = BN_CTX_new();
        if (bctx == NULL)
            return 0;
    }

    BN_CTX_start(bn_ctx);

    sum = BN_CTX_get(bn_ctx);
    product = BN_CTX_get(bn_ctx);
    one = BN_CTX_get(bn_ctx);
    if (one == NULL)
        goto err;

    BN_zero(sum);
    BN_one(one);

    num  = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_num(lc->items);
    for (i = 0; i < num; i++) {
        item = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_value(lc->items, i);
        if (item == NULL)
            goto err;

        var = item->variable;

        switch (var->type) {
        case BP_R1CS_VARIABLE_COMMITTED:
            a = sk_BIGNUM_value(witness->sk_v, var->value);
            break;
        case BP_R1CS_VARIABLE_MULTIPLIER_LEFT:
            a = sk_BIGNUM_value(ctx->aL, var->value);
            break;
        case BP_R1CS_VARIABLE_MULTIPLIER_RIGHT:
            a = sk_BIGNUM_value(ctx->aR, var->value);
            break;
        case BP_R1CS_VARIABLE_MULTIPLIER_OUTPUT:
            a = sk_BIGNUM_value(ctx->aO, var->value);
            break;
        case BP_R1CS_VARIABLE_ONE:
        default:
            a = one;
        }

        if (!BN_mul(product, a, item->scalar, bn_ctx)
            || !BN_add(sum, sum, product))
            goto err;
    }

    BN_copy(r, sum);
    ret = 1;

err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    return ret;
}

/*
 * left = lc(l)
 * right = lc(r)
 * output = left * right
 */
int BP_R1CS_LINEAR_COMBINATION_raw_mul(BP_R1CS_LINEAR_COMBINATION **output,
                                       BP_R1CS_LINEAR_COMBINATION **left,
                                       BP_R1CS_LINEAR_COMBINATION **right,
                                       const BIGNUM *l, const BIGNUM *r,
                                       BP_R1CS_CTX *ctx)
{
    int ln, rn, on, ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *lb = NULL, *rb = NULL, *ob = NULL;
    BP_R1CS_VARIABLE *lv = NULL, *rv = NULL, *ov = NULL;
    BP_R1CS_LINEAR_COMBINATION *llc = NULL, *rlc = NULL, *olc = NULL;

    if (output == NULL || ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (l != NULL && r != NULL) {
        ln  = sk_BIGNUM_num(ctx->aL);
        rn  = sk_BIGNUM_num(ctx->aR);
        on  = sk_BIGNUM_num(ctx->aO);

        bn_ctx = BN_CTX_new();
        if (bn_ctx == NULL)
            goto err;

        lb = BN_dup(l);
        rb = BN_dup(r);
        ob = BN_new();
        if (lb == NULL || rb == NULL || ob == NULL)
            goto err;

        if (!BN_mul(ob, lb, rb, bn_ctx))
            goto err;

        if (sk_BIGNUM_push(ctx->aL, lb) <= 0)
            goto err;
        lb = NULL;

        if (sk_BIGNUM_push(ctx->aR, rb) <= 0)
            goto err;
        rb = NULL;

        if (sk_BIGNUM_push(ctx->aO, ob) <= 0)
            goto err;
        ob = NULL;
    } else {
        ln = rn = on = ctx->vars_num;
        ctx->vars_num += 1;
    }

    ov = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_MULTIPLIER_OUTPUT, on);
    if (ov == NULL)
        goto err;

    olc = BP_R1CS_LINEAR_COMBINATION_new_from_param(ov, NULL);
    if (olc == NULL) {
        goto err;
    }

    *output = olc;

    if (left != NULL) {
        lv = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_MULTIPLIER_LEFT, ln);
        if (lv == NULL)
            goto err;

        llc = BP_R1CS_LINEAR_COMBINATION_new_from_param(lv, NULL);
        if (llc == NULL) {
            goto err;
        }

        *left = llc;
    }

    if (right != NULL) {
        rv = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_MULTIPLIER_RIGHT, rn);
        if (rv == NULL)
            goto err;

        rlc = BP_R1CS_LINEAR_COMBINATION_new_from_param(rv, NULL);
        if (rlc == NULL) {
            goto err;
        }

        *right = rlc;
    }

    BP_R1CS_VARIABLE_free(lv);
    BP_R1CS_VARIABLE_free(rv);
    BP_R1CS_VARIABLE_free(ov);
    BN_CTX_free(bn_ctx);
    return 1;
err:
    if (output == NULL)
        output = NULL;
    if (left == NULL)
        left = NULL;
    if (right == NULL)
        right = NULL;

    BP_R1CS_LINEAR_COMBINATION_free(llc);
    BP_R1CS_LINEAR_COMBINATION_free(rlc);
    BP_R1CS_LINEAR_COMBINATION_free(olc);
    BP_R1CS_VARIABLE_free(lv);
    BP_R1CS_VARIABLE_free(rv);
    BP_R1CS_VARIABLE_free(ov);
    BN_free(lb);
    BN_free(rb);
    BN_free(ob);
    BN_CTX_free(bn_ctx);
    return ret;
}

/* lc *= other */
int BP_R1CS_LINEAR_COMBINATION_mul(BP_R1CS_LINEAR_COMBINATION *lc,
                                   const BP_R1CS_LINEAR_COMBINATION *other,
                                   BP_R1CS_CTX *ctx)
{
    int ln, rn, on, ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *l = NULL, *r = NULL, *o = NULL, *bn_1;
    BP_R1CS_VARIABLE *lv = NULL, *rv = NULL, *ov = NULL;
    BP_R1CS_LINEAR_COMBINATION_ITEM *li = NULL, *ri = NULL, *oi = NULL;
    BP_R1CS_LINEAR_COMBINATION *llc = NULL, *rlc = NULL;
    STACK_OF(BP_R1CS_LINEAR_COMBINATION_ITEM) *lc_items = NULL;

    if (lc == NULL || other == NULL || ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (lc->type != BP_R1CS_LC_TYPE_UNKOWN && lc->type != other->type) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return 0;

    BN_CTX_start(bn_ctx);

    bn_1 = BN_CTX_get(bn_ctx);
    if (bn_1 == NULL)
        goto err;

    BN_one(bn_1);
    BN_set_negative(bn_1, 1);

    if (lc->type == BP_R1CS_LC_TYPE_PROVE) {
        l = BN_new();
        r = BN_new();
        o = BN_new();
        if (l == NULL || r == NULL || o == NULL)
            goto err;

        if (!BP_R1CS_LINEAR_COMBINATION_eval(ctx, lc, l, bn_ctx)
            || !BP_R1CS_LINEAR_COMBINATION_eval(ctx, other, r, bn_ctx))
            goto err;

        if (!BN_mul(o, l, r, bn_ctx))
            goto err;

        ln  = sk_BIGNUM_num(ctx->aL);
        rn  = sk_BIGNUM_num(ctx->aR);
        on  = sk_BIGNUM_num(ctx->aO);

        if (sk_BIGNUM_push(ctx->aL, l) <= 0)
            goto err;
        l = NULL;

        if (sk_BIGNUM_push(ctx->aR, r) <= 0)
            goto err;
        r = NULL;

        if (sk_BIGNUM_push(ctx->aO, o) <= 0)
            goto err;
        o = NULL;
    } else {
        ln = rn = on = ctx->vars_num;
        ctx->vars_num += 1;
    }

    llc = BP_R1CS_LINEAR_COMBINATION_dup(lc);
    rlc = BP_R1CS_LINEAR_COMBINATION_dup(other);
    if (llc == NULL || rlc == NULL)
        goto err;

    lv = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_MULTIPLIER_LEFT, ln);
    rv = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_MULTIPLIER_RIGHT, rn);
    ov = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_MULTIPLIER_OUTPUT, on);
    if (lv == NULL || rv == NULL || ov == NULL)
        goto err;

    if ((li = BP_R1CS_LC_ITEM_new(lv, bn_1)) == NULL
        || sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(llc->items, li) <= 0)
        goto err;
    li = NULL;

    if ((ri = BP_R1CS_LC_ITEM_new(rv, bn_1)) == NULL
        || sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(rlc->items, ri) <= 0)
        goto err;
    ri = NULL;

    if (!BP_R1CS_LINEAR_COMBINATION_constrain(llc, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(rlc, ctx))
        goto err;

    if (!(lc_items = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_new_reserve(NULL, 1)))
        goto err;

    if ((oi = BP_R1CS_LC_ITEM_new(ov, NULL)) == NULL
        || sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(lc_items, oi) <= 0)
        goto err;

    sk_BP_R1CS_LINEAR_COMBINATION_ITEM_pop_free(lc->items, BP_R1CS_LC_ITEM_free);
    lc->items = lc_items;
    lc_items = NULL;
    oi = NULL;
    llc = rlc = NULL;

    ret = 1;

err:
    sk_BP_R1CS_LINEAR_COMBINATION_ITEM_free(lc_items);
    BP_R1CS_LINEAR_COMBINATION_free(llc);
    BP_R1CS_LINEAR_COMBINATION_free(rlc);
    BP_R1CS_LC_ITEM_free(li);
    BP_R1CS_LC_ITEM_free(ri);
    BP_R1CS_LC_ITEM_free(oi);
    BP_R1CS_VARIABLE_free(lv);
    BP_R1CS_VARIABLE_free(rv);
    BP_R1CS_VARIABLE_free(ov);
    BN_free(l);
    BN_free(r);
    BN_free(o);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

/* lc += other */
int BP_R1CS_LINEAR_COMBINATION_add(BP_R1CS_LINEAR_COMBINATION *lc,
                                   const BP_R1CS_LINEAR_COMBINATION *other)
{
    int i, num;
    BP_R1CS_LINEAR_COMBINATION_ITEM *item = NULL, *p;

    if (lc == NULL || other == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    num  = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_num(other->items);
    for (i = 0; i < num; i++) {
        p = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_value(other->items, i);
        if (p == NULL)
            goto err;

        if ((item = BP_R1CS_LC_ITEM_dup(p)) == NULL)
            goto err;

        if (sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(lc->items, item) <= 0)
            goto err;
    }

    return 1;
err:
    BP_R1CS_LC_ITEM_free(item);
    return 0;
}

/* lc -= other */
int BP_R1CS_LINEAR_COMBINATION_sub(BP_R1CS_LINEAR_COMBINATION *lc,
                                   const BP_R1CS_LINEAR_COMBINATION *other)
{
    int i, num;
    BP_R1CS_LINEAR_COMBINATION_ITEM *item = NULL, *p;

    if (lc == NULL || other == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    num  = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_num(other->items);
    for (i = 0; i < num; i++) {
        p = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_value(other->items, i);
        if (p == NULL)
            goto err;

        if ((item = BP_R1CS_LC_ITEM_dup(p)) == NULL)
            goto err;

        BN_set_negative(item->scalar, 1);

        if (sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(lc->items, item) <= 0)
            goto err;
    }

    return 1;
err:
    BP_R1CS_LC_ITEM_free(item);
    return 0;
}

/* lc = -lc */
int BP_R1CS_LINEAR_COMBINATION_neg(BP_R1CS_LINEAR_COMBINATION *lc)
{
    int i, num, ret = 0;
    BP_R1CS_LINEAR_COMBINATION_ITEM *item;

    if (lc == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    num  = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_num(lc->items);
    for (i = 0; i < num; i++) {
        item = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_value(lc->items, i);
        if (item == NULL || item->scalar == NULL)
            goto err;

        BN_set_negative(item->scalar, 1);
    }

    ret = 1;

err:
    return ret;
}

/* lc = lc * value */
int BP_R1CS_LINEAR_COMBINATION_mul_bn(BP_R1CS_LINEAR_COMBINATION *lc,
                                      const BIGNUM *value)
{
    int i, num, ret = 0;
    BN_CTX *bn_ctx = NULL;
    BP_R1CS_LINEAR_COMBINATION_ITEM *item;

    if (lc == NULL || value == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!(bn_ctx = BN_CTX_new()))
        goto err;

    num  = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_num(lc->items);
    for (i = 0; i < num; i++) {
        item = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_value(lc->items, i);
        if (item == NULL || item->scalar == NULL)
            goto err;

        if (!BN_mul(item->scalar, item->scalar, value, bn_ctx))
            goto err;
    }

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

/* lc = lc + value */
int BP_R1CS_LINEAR_COMBINATION_add_bn(BP_R1CS_LINEAR_COMBINATION *lc,
                                      const BIGNUM *value)
{
    BP_R1CS_LINEAR_COMBINATION_ITEM *item;

    if (lc == NULL || value == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((item = BP_R1CS_LC_ITEM_new(NULL, value)) == NULL)
        return 0;

    if (sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(lc->items, item) <= 0) {
        BP_R1CS_LC_ITEM_free(item);
        return 0;
    }

    return 1;
}

/* lc = lc - value */
int BP_R1CS_LINEAR_COMBINATION_sub_bn(BP_R1CS_LINEAR_COMBINATION *lc,
                                      const BIGNUM *value)
{
    int ret = 0;
    BIGNUM *scalar = NULL;

    if (lc == NULL || value == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!(scalar = BN_dup(value)))
        return 0;

    BN_set_negative(scalar, 1);

    ret = BP_R1CS_LINEAR_COMBINATION_add_bn(lc, scalar);

    BN_free(scalar);
    return ret;
}

int BP_R1CS_LINEAR_COMBINATION_constrain(BP_R1CS_LINEAR_COMBINATION *lc,
                                         BP_R1CS_CTX *ctx)
{
    int ref;

    if (ctx == NULL || lc == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (CRYPTO_UP_REF(&lc->references, &ref, lc->lock) <= 0)
        return 0;

    if (sk_BP_R1CS_LINEAR_COMBINATION_push(ctx->constraints, lc) <= 0)
        goto err;

    return 1;
err:
    CRYPTO_DOWN_REF(&lc->references, &ref, lc->lock);
    return 0;
}

