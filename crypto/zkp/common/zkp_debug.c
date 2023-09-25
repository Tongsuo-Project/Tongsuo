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
#include <crypto/ec/ec_local.h>
#include "zkp_debug.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)

int zkp_rand_range_debug_one(BIGNUM *rnd, const BIGNUM *range)
{
    BN_set_word(rnd, 1);
    return 1;
}

int zkp_buf2hexstr_print(BIO *bio, const unsigned char *buf, size_t size,
                        char *field, int text)
{
    unsigned char *out = NULL;
    size_t out_n;
    BIO *b = NULL;

    if (bio == NULL) {
        bio = b = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    BIO_printf(bio, "%s: ", field);

    if (text) {
        BIO_puts(bio, "\n");
        BIO_indent(bio, 4, 4);
        BIO_hex_string(bio, 4, 16, buf, size);
    } else {
        out_n = size * 2 + 1;
        if (!(out = (unsigned char *)OPENSSL_zalloc(out_n))
            || !OPENSSL_buf2hexstr_ex((char *)out, out_n, NULL, buf, size, '\0')) {
            OPENSSL_free(out);
            return 0;
        }
        BIO_printf(bio, "%s", out);
        OPENSSL_free(out);
    }

    BIO_puts(bio, "\n");
    BIO_free(b);
    return 1;
}


void BN_debug_print(BIO *b, const BIGNUM *n, const char *name)
{
    BIO *bi = NULL;

    if (b == NULL) {
        b = bi = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    BIO_printf(b, "%s: ", name);
    BN_print(b, n);
    BIO_printf(b, "\n");

    BIO_free(bi);
}

void EC_POINT_debug_print(BIO *b, const EC_POINT *p, const char *name)
{
    BIO *bi = NULL;

    if (b == NULL) {
        b = bi = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    BIO_printf(b, "%s->X: ", name);
    BN_print(b, p->X);
    BIO_printf(b, ", %s->Y: ", name);
    BN_print(b, p->Y);
    BIO_printf(b, ", %s->Z: ", name);
    BN_print(b, p->Z);
    BIO_printf(b, "\n");

    BIO_free(bi);
}

void EC_POINT_debug_print_affine(BIO *b, const EC_GROUP *group, const EC_POINT *p,
                                 const char *name, BN_CTX *ctx)
{
    BIO *bi = NULL;
    BIGNUM *x, *y;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL)
        return;

    if (b == NULL) {
        b = bi = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    if (ctx == NULL) {
        bn_ctx = ctx = BN_CTX_new();
        if (bn_ctx == NULL)
            goto err;
    }

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto err;

    EC_POINT_get_affine_coordinates(group, p, x, y, ctx);

    BIO_printf(b, "%s->x: ", name);
    BN_print(b, x);
    BIO_printf(b, ", %s->y: ", name);
    BN_print(b, y);
    BIO_printf(b, "\n");

err:
    BN_CTX_end(ctx);
    BN_CTX_free(bn_ctx);
    BIO_free(bi);
}

void zkp_bn_vector_debug_print(BIO *bio, BIGNUM **bv, int n, const char *note)
{
    int i;

    if (bv == NULL)
        return;

    for (i = 0; i < n; i++) {
        BN_debug_print(bio, bv[i], note);
    }
}

void zkp_point_vector_debug_print(BIO *bio, const EC_GROUP *group, EC_POINT **pv,
                                  int n, const char *note, BN_CTX *bn_ctx)
{
    int i;

    if (group == NULL || pv == NULL)
        return;

    for (i = 0; i < n; i++) {
        EC_POINT_debug_print_affine(bio, group, pv[i], note, bn_ctx);
    }
}

void zkp_stack_of_bignum_debug_print(BIO *bio, STACK_OF(BIGNUM) *sk, const char *name)
{
    BIO *b = NULL;
    int i, n;
    BIGNUM *bn;

    if (sk == NULL)
        return;

    if (bio == NULL) {
        b = bio = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    n = sk_BIGNUM_num(sk);
    for (i = 0; i < n; i++) {
        bn = sk_BIGNUM_value(sk, i);
        if (bn == NULL)
            goto err;

        BIO_printf(bio, "%s[%d]: ", name, i);
        BN_print(bio, bn);
        BIO_printf(bio, "\n");
    }

err:
    BIO_free(b);
}

void zkp_stack_of_point_debug_print(BIO *bio, STACK_OF(EC_POINT) *sk, const char *name)
{
    BIO *b = NULL;
    int i, n;
    EC_POINT *p;

    if (sk == NULL)
        return;

    if (bio == NULL) {
        b = bio = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    n = sk_EC_POINT_num(sk);
    for (i = 0; i < n; i++) {
        p = sk_EC_POINT_value(sk, i);
        if (p == NULL)
            goto err;

        BIO_printf(b, "%s[%d]->X: ", name, i);
        BN_print(b, p->X);
        BIO_printf(b, ", %s[%d]->Y: ", name, i);
        BN_print(b, p->Y);
        BIO_printf(b, ", %s[%d]->Z: ", name, i);
        BN_print(b, p->Z);
        BIO_printf(b, "\n");
    }

err:
    BIO_free(b);
}
