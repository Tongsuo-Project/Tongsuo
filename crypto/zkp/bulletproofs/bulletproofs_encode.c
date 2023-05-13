/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <crypto/ec/ec_local.h>
#include "internal/endian.h"
#include "bulletproofs.h"
#include "range_proof.h"

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

static point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;

static int bp_stack_of_variable_encode(STACK_OF(BP_VARIABLE) *sk, unsigned char *out,
                                       const EC_GROUP *group, BN_CTX *bn_ctx)
{
    int i, n, *q, size;
    size_t point_len;
    unsigned char *p;
    BP_VARIABLE *V;

    if (sk == NULL || group == NULL)
        return 0;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    n = sk_BP_VARIABLE_num(sk);
    if (out == NULL) {
        size = sizeof(n) + n * point_len;
        for (i = 0; i < n; i++) {
            V = sk_BP_VARIABLE_value(sk, i);
            if (V == NULL)
                break;
            size += strlen(V->name);
        }

        return size;
    }

    q = (int *)out;
    *q++ = l2n((int)n);
    p = (unsigned char *)q;

    for (i = 0; i < n; i++) {
        V = sk_BP_VARIABLE_value(sk, i);
        if (V == NULL)
            goto end;

        if (EC_POINT_point2oct(group, V->point, form, p, point_len, bn_ctx) == 0)
            goto end;

        p += point_len;
        stpcpy((char *)p, V->name);
        p += strlen(V->name) + 1;
    }

end:
    return p - out;
}

static STACK_OF(BP_VARIABLE) *bp_stack_of_variable_decode(const unsigned char *in,
                                                          int *len,
                                                          const EC_GROUP *group,
                                                          BN_CTX *bn_ctx)
{
    char *name;
    unsigned char *p;
    int *q = (int *)in, n, i;
    size_t point_len;
    EC_POINT *V = NULL;
    BP_VARIABLE *var = NULL;
    STACK_OF(BP_VARIABLE) *ret = NULL;

    if (in == NULL || group == NULL)
        return 0;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    n = (int)n2l(*q);
    q++;
    p = (unsigned char *)q;

    if (n < 0) {
        return NULL;
    }

    if (!(ret = sk_BP_VARIABLE_new_reserve(NULL, n)))
        return NULL;

    for (i = 0; i < n; i++) {
        if (!(V = EC_POINT_new(group)))
            goto err;

        if (!EC_POINT_oct2point(group, V, p, point_len, bn_ctx))
            goto err;

        p += point_len;

        name = (char *)p;
        p += strlen(name) + 1;

        if (!(var = BP_VARIABLE_new(name, V, group)))
            goto err;

        if (sk_BP_VARIABLE_push(ret, var) <= 0)
            goto err;

        EC_POINT_free(V);
    }

    if (len != NULL)
        *len = p - in;

    return ret;
err:
    EC_POINT_free(V);
    BP_VARIABLE_free(var);
    sk_BP_VARIABLE_pop_free(ret, BP_VARIABLE_free);
    return NULL;
}

static int bp_stack_of_bignum_encode(STACK_OF(BIGNUM) *sk, unsigned char *out,
                                     int bn_len)
{
    int i, n, *q;
    unsigned char *p;
    BIGNUM *b;

    n = sk ? sk_BIGNUM_num(sk) : 0;
    if (out == NULL)
        return sizeof(n) + n * bn_len;

    q = (int *)out;
    *q++ = l2n((int)n);
    p = (unsigned char *)q;

    for (i = 0; i < n; i++) {
        b = sk_BIGNUM_value(sk, i);
        if (b == NULL)
            goto end;

        if (!BN_bn2binpad(b, p, bn_len))
            goto end;

        p += bn_len;
    }

end:
    return p - out;
}

static STACK_OF(BIGNUM) *bp_stack_of_bignum_decode(const unsigned char *in,
                                                   int *len, int bn_len)
{
    unsigned char *p;
    int *q = (int *)in, n, i;
    BIGNUM *b = NULL;
    STACK_OF(BIGNUM) *ret;

    n = (int)n2l(*q);
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

        if (!BN_bin2bn(p, (int)bn_len, b))
            goto err;

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

static int bp_stack_of_point_encode(STACK_OF(EC_POINT) *sk, unsigned char *out,
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

static STACK_OF(EC_POINT) *bp_stack_of_point_decode(const unsigned char *in,
                                                    int *len,
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

/** Encodes BP_PUB_PARAM to binary
 *  \param  pp         BP_PUB_PARAM object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_PUB_PARAM_encode(const BP_PUB_PARAM *pp, unsigned char *out, size_t size)
{
    int *q, sk_len, curve_id;
    size_t point_len, ret = 0, len;
    unsigned char *p;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    group = pp->group;

    curve_id = EC_GROUP_get_curve_name(group);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);

    sk_len = bp_stack_of_point_encode(pp->sk_G, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;

    len = sizeof(int) * 3 + point_len * 2 + sk_len * 2;
    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    q = (int *)out;
    *q++ = l2n((int)curve_id);
    *q++ = l2n((int)pp->gens_capacity);
    *q++ = l2n((int)pp->party_capacity);
    p = (unsigned char *)q;

    if (EC_POINT_point2oct(group, pp->H, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(group, pp->U, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    sk_len = bp_stack_of_point_encode(pp->sk_G, p, group, bn_ctx);
    if (sk_len == 0)
        goto end;

    p += sk_len;

    sk_len = bp_stack_of_point_encode(pp->sk_H, p, group, bn_ctx);
    if (sk_len == 0)
        goto end;

    p += sk_len;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Decodes binary to BP_PUB_PARAM
 *  \param  in         Memory buffer with the encoded BP_PUB_PARAM
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_PUB_PARAM object pointer on success and NULL otherwise
 */
BP_PUB_PARAM *BP_PUB_PARAM_decode(const unsigned char *in, size_t size)
{
    unsigned char *p;
    int curve_id, *q = (int *)in, sk_len;
    size_t point_len, gens_capacity, party_capacity, n;
    BP_PUB_PARAM *pp = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (in == NULL || size <= 12) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    curve_id = n2l(*q);
    q++;
    gens_capacity = (size_t)n2l(*q);
    q++;
    party_capacity = (size_t)n2l(*q);
    q++;
    p = (unsigned char *)q;
    n = gens_capacity * party_capacity;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    if (size < (sizeof(int) * 3 + point_len * (n * 2 + 2))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    pp = BP_PUB_PARAM_new(group, gens_capacity, party_capacity);
    if (pp == NULL)
        goto err;

    sk_EC_POINT_pop_free(pp->sk_G, EC_POINT_free);
    sk_EC_POINT_pop_free(pp->sk_H, EC_POINT_free);
    pp->sk_G = NULL;
    pp->sk_H = NULL;

    if (!EC_POINT_oct2point(group, pp->H, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!EC_POINT_oct2point(group, pp->U, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!(pp->sk_G = bp_stack_of_point_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    if (!(pp->sk_H = bp_stack_of_point_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return pp;

err:
    EC_GROUP_free(group);
    BP_PUB_PARAM_free(pp);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Encodes BP_WITNESS to binary
 *  \param  pp         BP_WITNESS object
 *  \param  out        The buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  flag       The flag is an indicator for encoding random number 'r'
 *                     and plaintext 'v', with 1 indicating encoding and 0
 *                     indicating no encoding.
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_WITNESS_encode(const BP_WITNESS *witness, unsigned char *out,
                         size_t size, int flag)
{
    int *q, curve_id, bn_len, sk_len;
    size_t ret = 0, len, n, point_len;
    unsigned char *p;
    BP_VARIABLE *V;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *order;
    EC_GROUP *group = NULL;

    if (witness == NULL || witness->sk_V == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    n = sk_BP_VARIABLE_num(witness->sk_V);
    if (n == 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return ret;
    }

    V = sk_BP_VARIABLE_value(witness->sk_V, 0);
    if ((curve_id = EC_POINT_get_curve_name(V->point)) == NID_undef) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto end;

    order = EC_GROUP_get0_order(group);
    bn_len = BN_num_bytes(order);

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(sk_len = bp_stack_of_variable_encode(witness->sk_V, NULL, group, bn_ctx)))
        goto end;

    len = 4 + point_len + sk_len;

    if (!(sk_len = bp_stack_of_bignum_encode(witness->sk_r, NULL, bn_len)))
        goto end;

    if (flag == 1)
        len += sk_len * 2;

    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    q = (int *)out;
    *q++ = l2n((int)curve_id);
    p = (unsigned char *)q;

    if (EC_POINT_point2oct(group, witness->H, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (!(sk_len = bp_stack_of_variable_encode(witness->sk_V, p, group, bn_ctx)))
        goto end;

    p += sk_len;

    if (flag == 1) {
        if (!(sk_len = bp_stack_of_bignum_encode(witness->sk_r, p, bn_len)))
            goto end;

        p += sk_len;

        if (!(sk_len = bp_stack_of_bignum_encode(witness->sk_v, p, bn_len)))
            goto end;

        p += sk_len;
    }

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}

/** Decodes binary to BP_WITNESS
 *  \param  in         Memory buffer with the encoded BP_WITNESS
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_WITNESS object pointer on success and NULL otherwise
 */
BP_WITNESS *BP_WITNESS_decode(const unsigned char *in, size_t size)
{
    unsigned char *p;
    int curve_id, *q = (int *)in, bn_len, sk_len, n;
    size_t point_len;
    BP_WITNESS *witness = NULL;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *order;
    EC_GROUP *group = NULL;

    if (in == NULL || size <= 12) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    curve_id = n2l(*q);
    q++;
    p = (unsigned char *)q;
    n = n2l(*q);

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    order = EC_GROUP_get0_order(group);
    bn_len = BN_num_bytes(order);

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    if (size < (4 * 2 + point_len * n)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        goto err;
    }

    if (!EC_POINT_oct2point(group, witness->H, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!(witness->sk_V = bp_stack_of_variable_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    if (!(witness->sk_r = bp_stack_of_bignum_decode(p, &sk_len, bn_len)))
        goto err;

    p += sk_len;

    if (!(witness->sk_v = bp_stack_of_bignum_decode(p, &sk_len, bn_len)))
        goto err;

    p += sk_len;

    witness->group = group;

    BN_CTX_free(bn_ctx);
    return witness;

err:
    EC_GROUP_free(group);
    BP_WITNESS_free(witness);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Encodes BP_RANGE_PROOF to binary
 *  \param  proof      BP_RANGE_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_RANGE_PROOF_encode(const BP_RANGE_PROOF *proof, unsigned char *out,
                             size_t size)
{
    int *q, curve_id, bn_len, ret = 0, sk_len;
    size_t len, point_len;
    unsigned char *p;
    bp_inner_product_proof_t *ip_proof;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *order;
    EC_GROUP *group = NULL;

    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    ip_proof = proof->ip_proof;

    if ((curve_id = EC_POINT_get_curve_name(proof->A)) == NID_undef
        || ip_proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    order = EC_GROUP_get0_order(group);
    bn_len = BN_num_bytes(order);

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    /* proof_len = len(curve_id) + len(A+S+T1+T2) + len(taux+mu+tx) */
    len = sizeof(int) + point_len * 4 + bn_len * 3;

    if (!(sk_len = bp_stack_of_point_encode(ip_proof->sk_L, NULL, group, bn_ctx)))
        goto end;

    /* ip_proof_len = len(a+b) + len(n) + len(sk_L+sk_R) */
    len += bn_len * 2 + sk_len * 2;

    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    /* encoding proof */
    q = (int *)out;
    *q++ = l2n(curve_id);
    p = (unsigned char *)q;

    if (EC_POINT_point2oct(group, proof->A, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(group, proof->S, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(group, proof->T1, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(group, proof->T2, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (!BN_bn2binpad(proof->taux, p, bn_len))
        goto end;

    p += bn_len;

    if (!BN_bn2binpad(proof->mu, p, bn_len))
        goto end;

    p += bn_len;

    if (!BN_bn2binpad(proof->tx, p, bn_len))
        goto end;

    p += bn_len;

    /* encoding ip_proof */
    if (!BN_bn2binpad(ip_proof->a, p, bn_len))
        goto end;

    p += bn_len;

    if (!BN_bn2binpad(ip_proof->b, p, bn_len))
        goto end;

    p += bn_len;

    if (!(sk_len = bp_stack_of_point_encode(ip_proof->sk_L, p, group, bn_ctx)))
        goto end;

    p += sk_len;

    if (!(sk_len = bp_stack_of_point_encode(ip_proof->sk_R, p, group, bn_ctx)))
        goto end;

    p += sk_len;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}

/** Decodes binary to BP_RANGE_PROOF
 *  \param  in         Memory buffer with the encoded BP_RANGE_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_RANGE_PROOF_PUB_PARAM object pointer on success and NULL otherwise
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_decode(const unsigned char *in, size_t size)
{
    unsigned char *p;
    int *q = (int *)in, curve_id, sk_len;
    size_t point_len, bn_len, proof_len;
    BP_RANGE_PROOF *proof = NULL;
    bp_inner_product_proof_t *ip_proof = NULL;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *order;
    EC_GROUP *group = NULL;

    if (in == NULL || size <= 8) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    curve_id = n2l(*q);
    q++;

    if (curve_id <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    p = (unsigned char *)q;

    order = EC_GROUP_get0_order(group);
    bn_len = BN_num_bytes(order);

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    /* len(curve_id) + len(A+S+T1+T2) + len(taux+mu+tx) */
    proof_len = 4 + point_len * 4 + bn_len * 3;
    if (size < proof_len) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    proof = bp_range_proof_alloc(group);
    if (proof == NULL)
        goto err;

    if (!EC_POINT_oct2point(group, proof->A, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!EC_POINT_oct2point(group, proof->S, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!EC_POINT_oct2point(group, proof->T1, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!EC_POINT_oct2point(group, proof->T2, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!BN_bin2bn(p, (int)bn_len, proof->taux))
        goto err;

    p += bn_len;

    if (!BN_bin2bn(p, (int)bn_len, proof->mu))
        goto err;

    p += bn_len;

    if (!BN_bin2bn(p, (int)bn_len, proof->tx))
        goto err;

    p += bn_len;

    if (!(ip_proof = bp_inner_product_proof_alloc(1)))
        goto err;

    sk_EC_POINT_free(ip_proof->sk_L);
    sk_EC_POINT_free(ip_proof->sk_R);
    ip_proof->sk_L = NULL;
    ip_proof->sk_R = NULL;

    if (!BN_bin2bn(p, (int)bn_len, ip_proof->a))
        goto err;

    p += bn_len;

    if (!BN_bin2bn(p, (int)bn_len, ip_proof->b))
        goto err;

    p += bn_len;

    if (!(ip_proof->sk_L = bp_stack_of_point_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    if (!(ip_proof->sk_R = bp_stack_of_point_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    proof->ip_proof = ip_proof;

    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return proof;

err:
    bp_inner_product_proof_free(ip_proof);
    BP_RANGE_PROOF_free(proof);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return NULL;
}
