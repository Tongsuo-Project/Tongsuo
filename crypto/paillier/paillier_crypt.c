/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include "paillier_local.h"

int PAILLIER_encrypt(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *out, int32_t m)
{
    int ret = 0;
    PAILLIER_KEY *key;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *r, *r_exp_n, *g_exp_m, *bn_plain;

    if (ctx == NULL || out == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    key = ctx->key;

    bn_plain = BN_CTX_get(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    r_exp_n = BN_CTX_get(bn_ctx);
    g_exp_m = BN_CTX_get(bn_ctx);
    if (g_exp_m == NULL)
        goto err;

    BN_set_word(bn_plain, (BN_ULONG)(m > 0 ? m : -m));
    BN_set_negative(bn_plain, m < 0 ? 1 : 0);

    if (!BN_rand_range(r, key->n))
        goto err;

    if (!BN_mod_exp(r_exp_n, r, key->n, key->n_square, bn_ctx))
        goto err;

    if (key->flag & PAILLIER_FLAG_G_OPTIMIZE) {
        if (!BN_mul(g_exp_m, bn_plain, key->n, bn_ctx))
            goto err;

        if (!BN_add_word(g_exp_m, (BN_ULONG)1))
            goto err;

        if (!BN_mod(g_exp_m, g_exp_m, key->n_square, bn_ctx))
            goto err;
    } else {
        if (!BN_mod_exp(g_exp_m, key->g, bn_plain, key->n_square, bn_ctx))
            goto err;

        if (m < 0)
            ret = BN_mod_inverse(g_exp_m, g_exp_m, key->n_square, bn_ctx);
    }

    if (!BN_mod_mul(out->data, g_exp_m, r_exp_n, key->n_square, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

int PAILLIER_decrypt(PAILLIER_CTX *ctx, int32_t *out, PAILLIER_CIPHERTEXT *c)
{
    int ret = 0;
    int32_t result;
    char *p = NULL;
    PAILLIER_KEY *key;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *c_exp_lambda, *l_ret, *bn_out;

    if (ctx == NULL || out == NULL || c == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    key = ctx->key;

    bn_out = BN_CTX_get(bn_ctx);
    c_exp_lambda = BN_CTX_get(bn_ctx);
    l_ret = BN_CTX_get(bn_ctx);
    if (l_ret == NULL)
        goto err;

    if (!BN_mod_exp(c_exp_lambda, c->data, key->lambda, key->n_square, bn_ctx))
        goto err;

    if (!paillier_l_func(l_ret, c_exp_lambda, key->n, bn_ctx))
        goto err;

    if (!BN_mod_mul(bn_out, l_ret, key->u, key->n, bn_ctx))
        goto err;

    if (BN_cmp(bn_out, ctx->threshold) == 1) {
        if (!BN_sub(bn_out, bn_out, key->n))
            goto err;
    }

    p = BN_bn2dec(bn_out);
    if (p == NULL)
        goto err;

    result = atoi(p);
    if (result == 0 && *p != '0')
        goto err;

    *out = result;
    ret = 1;

err:
    OPENSSL_free(p);
    BN_CTX_free(bn_ctx);
    return ret;
}

int PAILLIER_add(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c1, PAILLIER_CIPHERTEXT *c2)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || r == NULL || c1 == NULL || c2 == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return 0;

    ret = BN_mod_mul(r->data, c1->data, c2->data, ctx->key->n_square, bn_ctx);

    BN_CTX_free(bn_ctx);
    return ret;
}

int PAILLIER_add_plain(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                       PAILLIER_CIPHERTEXT *c, int32_t m)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *g_exp_p, *l_ret, *bn_plain;

    if (ctx == NULL || r == NULL || c == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    bn_plain = BN_CTX_get(bn_ctx);
    g_exp_p = BN_CTX_get(bn_ctx);
    if (g_exp_p == NULL)
        goto err;

    BN_set_word(bn_plain, (BN_ULONG)(m > 0 ? m : -(int64_t)m));
    BN_set_negative(bn_plain, m < 0 ? 1 : 0);

    if (!BN_mod_exp(g_exp_p, ctx->key->g, bn_plain, ctx->key->n_square, bn_ctx))
        goto err;

    ret = BN_mod_mul(r->data, c->data, g_exp_p, ctx->key->n_square, bn_ctx);

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

int PAILLIER_sub(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c1, PAILLIER_CIPHERTEXT *c2)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *inv;

    if (ctx == NULL || r == NULL || c1 == NULL || c2 == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return 0;

    inv = BN_CTX_get(bn_ctx);
    if (inv == NULL)
        goto err;

    if (!BN_mod_inverse(inv, c2->data, ctx->key->n_square, bn_ctx))
        goto err;

    ret = BN_mod_mul(r->data, c1->data, inv, ctx->key->n_square, bn_ctx);

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

int PAILLIER_mul(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c, int32_t m)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_plain;

    if (ctx == NULL || r == NULL || c == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    bn_plain = BN_CTX_get(bn_ctx);
    if (bn_plain == NULL)
        goto err;

    BN_set_word(bn_plain, (BN_ULONG)(m > 0 ? m : -m));

    ret = BN_mod_exp(r->data, c->data, bn_plain, ctx->key->n_square, bn_ctx);
    if (m < 0)
        ret = BN_mod_inverse(r->data, r->data, ctx->key->n_square, bn_ctx) != NULL;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}
