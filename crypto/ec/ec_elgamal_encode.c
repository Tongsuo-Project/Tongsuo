/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "ec_elgamal.h"
#include <openssl/err.h>
#include <string.h>

#ifdef __bswap_constant_32
# undef __bswap_constant_32
#endif
#define __bswap_constant_32(x)                  \
    ((((uint32_t)(x) & 0xff000000u) >> 24) |    \
     (((uint32_t)(x) & 0x00ff0000u) >>  8) |    \
     (((uint32_t)(x) & 0x0000ff00u) <<  8) |    \
     (((uint32_t)(x) & 0x000000ffu) << 24))

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define n2l(x)  (x)
# define l2n(x)  (x)
#else
# define n2l(x)  __bswap_constant_32(x)
# define l2n(x)  __bswap_constant_32(x)
#endif

DEFINE_STACK_OF(EC_POINT)

static int stack_of_point_encode(STACK_OF(EC_POINT) *sk, unsigned char *out,
                                 point_conversion_form_t form,
                                 const EC_GROUP *group, BN_CTX *bn_ctx)
{
    int i, n, *q;
    size_t point_len;
    unsigned char *p = out;
    EC_POINT *P;

    if (sk == NULL || group == NULL)
        return 0;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    n = sk_EC_POINT_num(sk);
    if (out == NULL)
        return 1 + sizeof(n) + n * point_len;

    *p++ = form == POINT_CONVERSION_COMPRESSED ? 0x1 : 0;

    q = (int *)p;
    *q++ = l2n((int)n);
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

static STACK_OF(EC_POINT) *stack_of_point_decode(const unsigned char *in,
                                                 int *len,
                                                 const EC_GROUP *group,
                                                 BN_CTX *bn_ctx)
{
    unsigned char *p = (unsigned char *)in;
    int *q, n, i;
    size_t point_len;
    EC_POINT *P = NULL;
    STACK_OF(EC_POINT) *ret = NULL;
    point_conversion_form_t form;

    if (in == NULL || group == NULL)
        return 0;

    form = *p == 0x1 ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    p++;
    q = (int *)p;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);

    n = (int)n2l(*q);
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

/** Creates a new EC_ELGAMAL_CIPHERTEXT object for EC-ELGAMAL oparations
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \return newly created EC_ELGAMAL_CIPHERTEXT object or NULL in case of an error
 */
EC_ELGAMAL_CIPHERTEXT *EC_ELGAMAL_CIPHERTEXT_new(EC_ELGAMAL_CTX *ctx)
{
    EC_POINT *C1 = NULL, *C2 = NULL;
    EC_ELGAMAL_CIPHERTEXT *ciphertext;

    ciphertext = OPENSSL_zalloc(sizeof(*ciphertext));
    if (ciphertext == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    C1 = EC_POINT_new(ctx->key->group);
    if (C1 == NULL)
        goto err;

    C2 = EC_POINT_new(ctx->key->group);
    if (C2 == NULL)
        goto err;

    ciphertext->C1 = C1;
    ciphertext->C2 = C2;

    return ciphertext;

err:
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    OPENSSL_free(ciphertext);
    return NULL;
}

EC_ELGAMAL_CIPHERTEXT *EC_ELGAMAL_CIPHERTEXT_dup(const EC_ELGAMAL_CIPHERTEXT *ct,
                                                 const EC_GROUP *group)
{
    EC_ELGAMAL_CIPHERTEXT *ret;

    if (ct == NULL || group == NULL)
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->C1 = EC_POINT_dup(ct->C1, group);
    ret->C2 = EC_POINT_dup(ct->C2, group);
    if (ret->C1 == NULL || ret->C2 == NULL)
        goto err;

    return ret;

err:
    EC_ELGAMAL_CIPHERTEXT_free(ret);
    return NULL;
}

/** Frees a EC_ELGAMAL_CIPHERTEXT object
 *  \param  ciphertext  EC_ELGAMAL_CIPHERTEXT object to be freed
 */
void EC_ELGAMAL_CIPHERTEXT_free(EC_ELGAMAL_CIPHERTEXT *ciphertext)
{
    if (ciphertext == NULL)
        return;

    EC_POINT_free(ciphertext->C1);
    EC_POINT_free(ciphertext->C2);

    OPENSSL_free(ciphertext);
}

/** Encodes EC_ELGAMAL_CIPHERTEXT to binary
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  ciphertext EC_ELGAMAL_CIPHERTEXT object
 *  \param  compressed Whether to compress the encoding (either 0 or 1)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t EC_ELGAMAL_CIPHERTEXT_encode(EC_ELGAMAL_CTX *ctx, unsigned char *out,
                                    size_t size,
                                    const EC_ELGAMAL_CIPHERTEXT *ciphertext,
                                    int compressed)
{
    size_t point_len, ret = 0, len, plen;
    unsigned char *p = out;
    point_conversion_form_t form = compressed ? POINT_CONVERSION_COMPRESSED :
                                                POINT_CONVERSION_UNCOMPRESSED;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || ciphertext == NULL ||
        ciphertext->C1 == NULL || ciphertext->C2 == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    point_len = EC_POINT_point2oct(ctx->key->group,
                                   EC_GROUP_get0_generator(ctx->key->group),
                                   form, NULL, 0, bn_ctx);
    len = point_len * 2;
    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    plen = EC_POINT_point2oct(ctx->key->group, ciphertext->C1, form, p,
                              point_len, bn_ctx);
    if (plen == 0)
        goto end;

    p += point_len;

    plen = EC_POINT_point2oct(ctx->key->group, ciphertext->C2, form, p,
                              point_len, bn_ctx);
    if (plen == 0)
        goto end;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Decodes binary to EC_ELGAMAL_CIPHERTEXT
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          the resulting ciphertext
 *  \param  in         Memory buffer with the encoded EC_ELGAMAL_CIPHERTEXT
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_CIPHERTEXT_decode(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                                 unsigned char *in, size_t size)
{
    int ret = 0;
    size_t point_len;
    unsigned char *p = in, zero[128];
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || r->C1 == NULL ||
        r->C2 == NULL || size % 2 != 0 || in == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    point_len = size / 2;
    memset(zero, 0, sizeof(zero));

    if (!EC_POINT_oct2point(ctx->key->group, r->C1, p, point_len, bn_ctx)) {
        if (memcmp(p, zero, point_len) != 0 ||
            !EC_POINT_set_to_infinity(ctx->key->group, r->C1))
            goto err;
    }

    p += point_len;

    if (!EC_POINT_oct2point(ctx->key->group, r->C2, p, point_len, bn_ctx)) {
        if (memcmp(p, zero, point_len) != 0 ||
            !EC_POINT_set_to_infinity(ctx->key->group, r->C2))
            goto err;
    }

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Creates a new EC_ELGAMAL_MR_CIPHERTEXT object for EC-ELGAMAL oparations
 *  \param  ctx        EC_ELGAMAL_MR_CTX object
 *  \return newly created EC_ELGAMAL_MR_CIPHERTEXT object or NULL in case of an error
 */
EC_ELGAMAL_MR_CIPHERTEXT *EC_ELGAMAL_MR_CIPHERTEXT_new(EC_ELGAMAL_MR_CTX *ctx)
{
    STACK_OF(EC_POINT) *sk_C1 = NULL;
    EC_ELGAMAL_MR_CIPHERTEXT *ciphertext;
    EC_POINT *C2 = NULL;

    ciphertext = OPENSSL_zalloc(sizeof(*ciphertext));
    if (ciphertext == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    sk_C1 = sk_EC_POINT_new_null();
    if (sk_C1 == NULL)
        goto err;

    C2 = EC_POINT_new(ctx->group);
    if (C2 == NULL)
        goto err;

    ciphertext->sk_C1 = sk_C1;
    ciphertext->C2 = C2;

    return ciphertext;

err:
    sk_EC_POINT_free(sk_C1);
    EC_POINT_free(C2);
    OPENSSL_free(ciphertext);
    return NULL;
}

EC_ELGAMAL_MR_CIPHERTEXT *EC_ELGAMAL_MR_CIPHERTEXT_dup(const EC_ELGAMAL_MR_CIPHERTEXT *ct,
                                                       const EC_GROUP *group)
{
    int i;
    STACK_OF(EC_POINT) *sk_C1 = NULL;
    EC_ELGAMAL_MR_CIPHERTEXT *ret;
    EC_POINT *P = NULL, *C1, *C2 = NULL;

    if (ct == NULL || group == NULL)
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    sk_C1 = sk_EC_POINT_new_reserve(NULL, sk_EC_POINT_num(ct->sk_C1));
    if (sk_C1 == NULL)
        goto err;

    for (i = 0; i < sk_EC_POINT_num(ct->sk_C1); i++) {
        C1 = sk_EC_POINT_value(ct->sk_C1, i);
        if (!(P = EC_POINT_dup(C1, group)))
            goto err;

        if (sk_EC_POINT_push(sk_C1, P) <= 0)
            goto err;
    }

    C2 = EC_POINT_dup(ct->C2, group);
    if (C2 == NULL)
        goto err;

    ret->sk_C1 = sk_C1;
    ret->C2 = C2;

    return ret;

err:
    sk_EC_POINT_pop_free(sk_C1, EC_POINT_free);
    EC_POINT_free(P);
    EC_POINT_free(C2);
    OPENSSL_free(ret);
    return NULL;
}

/** Frees a EC_ELGAMAL_MR_CIPHERTEXT object
 *  \param  ciphertext  EC_ELGAMAL_MR_CIPHERTEXT object to be freed
 */
void EC_ELGAMAL_MR_CIPHERTEXT_free(EC_ELGAMAL_MR_CIPHERTEXT *ciphertext)
{
    if (ciphertext == NULL)
        return;

    sk_EC_POINT_pop_free(ciphertext->sk_C1, EC_POINT_free);
    EC_POINT_free(ciphertext->C2);

    OPENSSL_free(ciphertext);
}

/** Encodes EC_ELGAMAL_MR_CIPHERTEXT to binary
 *  \param  ctx        EC_ELGAMAL_MR_CTX object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  ciphertext EC_ELGAMAL_MR_CIPHERTEXT object
 *  \param  compressed Whether to compress the encoding (either 0 or 1)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t EC_ELGAMAL_MR_CIPHERTEXT_encode(EC_ELGAMAL_MR_CTX *ctx, unsigned char *out,
                                       size_t size,
                                       const EC_ELGAMAL_MR_CIPHERTEXT *ciphertext,
                                       int compressed)
{
    size_t point_len, ret = 0, len, plen;
    unsigned char *p = out;
    point_conversion_form_t form = compressed ? POINT_CONVERSION_COMPRESSED :
                                                POINT_CONVERSION_UNCOMPRESSED;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->group == NULL || ciphertext == NULL ||
        ciphertext->sk_C1 == NULL || ciphertext->C2 == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    point_len = EC_POINT_point2oct(ctx->group,
                                   EC_GROUP_get0_generator(ctx->group),
                                   form, NULL, 0, bn_ctx);

    len = stack_of_point_encode(ciphertext->sk_C1, NULL, form, ctx->group, bn_ctx);

    len += point_len;
    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    len = stack_of_point_encode(ciphertext->sk_C1, p, form, ctx->group, bn_ctx);
    if (len <= 0)
        goto end;

    p += len;

    plen = EC_POINT_point2oct(ctx->group, ciphertext->C2, form, p,
                              point_len, bn_ctx);
    if (plen == 0)
        goto end;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Decodes binary to EC_ELGAMAL_MR_CIPHERTEXT
 *  \param  ctx        EC_ELGAMAL_MR_CTX object
 *  \param  r          the resulting ciphertext
 *  \param  in         Memory buffer with the encoded EC_ELGAMAL_MR_CIPHERTEXT
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_MR_CIPHERTEXT_decode(EC_ELGAMAL_MR_CTX *ctx, EC_ELGAMAL_MR_CIPHERTEXT *r,
                                    unsigned char *in, size_t size)
{
    int ret = 0, len = 0;
    size_t point_len;
    unsigned char *p = in, zero[128];
    BN_CTX *bn_ctx = NULL;
    STACK_OF(EC_POINT) *sk_C1 = NULL;
    point_conversion_form_t form;

    if (ctx == NULL || ctx->group == NULL || r == NULL || r->C2 == NULL || in == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    memset(zero, 0, sizeof(zero));

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    form = *p == 0x1 ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;

    point_len = EC_POINT_point2oct(ctx->group, EC_GROUP_get0_generator(ctx->group),
                                   form, NULL, 0, bn_ctx);

    sk_C1 = stack_of_point_decode(p, &len, ctx->group, bn_ctx);
    p += len;

    if (!EC_POINT_oct2point(ctx->group, r->C2, p, point_len, bn_ctx)) {
        if (memcmp(p, zero, point_len) != 0 ||
            !EC_POINT_set_to_infinity(ctx->group, r->C2))
            goto err;
    }

    if (r->sk_C1 != NULL) {
        sk_EC_POINT_pop_free(r->sk_C1, EC_POINT_free);
    }

    r->sk_C1 = sk_C1;
    sk_C1 = NULL;
    ret = 1;

err:
    sk_EC_POINT_pop_free(sk_C1, EC_POINT_free);
    BN_CTX_free(bn_ctx);
    return ret;
}
