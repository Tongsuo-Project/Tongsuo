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
#include "bullet_proof.h"

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

/** Encodes BULLET_PROOF_PUB_PARAM to binary
 *  \param  pp         BULLET_PROOF_PUB_PARAM object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BULLET_PROOF_PUB_PARAM_encode(BULLET_PROOF_PUB_PARAM *pp, unsigned char *out,
                                     size_t size)
{
    int *q;
    size_t point_len, ret = 0, len, i, n;
    unsigned char *p;
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, pp->curve_id);
    if (group == NULL)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    n = pp->bits * pp->max_agg_num;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    len = 4 * 3 + point_len * (n * 2 + 2);
    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    q = (int *)out;
    *q++ = l2n((int)pp->curve_id);
    *q++ = l2n((int)pp->bits);
    *q++ = l2n((int)pp->max_agg_num);
    p = (unsigned char *)q;

    for (i = 0; i < n; i++) {
        if (EC_POINT_point2oct(group, pp->vec_G[i], form, p, point_len,
                               bn_ctx) == 0)
            goto end;

        p += point_len;
    }

    for (i = 0; i < n; i++) {
        if (EC_POINT_point2oct(group, pp->vec_H[i], form, p, point_len,
                               bn_ctx) == 0)
            goto end;

        p += point_len;
    }

    if (EC_POINT_point2oct(group, pp->H, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(group, pp->U, form, p, point_len, bn_ctx) == 0)
        goto end;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}

/** Decodes binary to BULLET_PROOF_PUB_PARAM
 *  \param  in         Memory buffer with the encoded BULLET_PROOF_PUB_PARAM
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return BULLET_PROOF_PUB_PARAM object pointer on success and NULL otherwise
 */
BULLET_PROOF_PUB_PARAM *BULLET_PROOF_PUB_PARAM_decode(unsigned char *in,
                                                      size_t size)
{
    unsigned char *p;
    int curve_id, *q = (int *)in;
    size_t point_len, bits, max_agg_num, n, i;
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
    BULLET_PROOF_PUB_PARAM *pp = NULL;
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
    bits = (size_t)n2l(*q);
    q++;
    max_agg_num = (size_t)n2l(*q);
    q++;
    p = (unsigned char *)q;
    n = bits * max_agg_num;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    if (size < (4 * 3 + point_len * (n * 2 + 2))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    pp = BULLET_PROOF_PUB_PARAM_new(curve_id, bits, max_agg_num);
    if (pp == NULL)
        goto err;

    for (i = 0; i < n; i++) {
        if (!EC_POINT_oct2point(group, pp->vec_G[i], p, point_len, bn_ctx))
            goto err;

        p += point_len;
    }

    for (i = 0; i < n; i++) {
        if (!EC_POINT_oct2point(group, pp->vec_H[i], p, point_len, bn_ctx))
            goto err;

        p += point_len;
    }

    if (!EC_POINT_oct2point(group, pp->H, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!EC_POINT_oct2point(group, pp->U, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return pp;

err:
    EC_GROUP_free(group);
    BULLET_PROOF_PUB_PARAM_free(pp);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Encodes BULLET_PROOF to binary
 *  \param  proof      BULLET_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BULLET_PROOF_encode(BULLET_PROOF *proof, unsigned char *out, size_t size)
{
    int *q, curve_id;
    size_t point_len, bn_len, ret = 0, len, i;
    unsigned char *p;
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *order;
    EC_GROUP *group = NULL;

    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    if ((curve_id = EC_POINT_get_curve_name(proof->A)) <= 0) {
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
    /* proof_len = len(curve_id) + len(n) + len(V[n]+A+S+T1+T2) + len(taux+mu+tx) */
    len = 4 + 4 + point_len * (proof->n + 4) + bn_len * 3;
    /* ip_proof_len = len(n) + len(vec_L[n]+vec_R[n]) + len(a+b) */
    len += 4 + point_len * proof->ip_proof->n * 2 + bn_len * 2;
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
    *q++ = l2n((int)proof->n);
    p = (unsigned char *)q;

    for (i = 0; i < proof->n; i++) {
        if (EC_POINT_point2oct(group, proof->V[i], form, p, point_len, bn_ctx) == 0)
            goto end;

        p += point_len;
    }

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

    if (!BN_bn2bin(proof->taux, p))
        goto end;

    p += bn_len;

    if (!BN_bn2bin(proof->mu, p))
        goto end;

    p += bn_len;

    if (!BN_bn2bin(proof->tx, p))
        goto end;

    p += bn_len;

    /* encoding ip_proof */
    q = (int *)p;
    *q++ = l2n((int)proof->ip_proof->n);
    p = (unsigned char *)q;

    for (i = 0; i < proof->ip_proof->n; i++) {
        if (EC_POINT_point2oct(group, proof->ip_proof->vec_L[i], form, p, point_len,
                               bn_ctx) == 0)
            goto end;

        p += point_len;
    }

    for (i = 0; i < proof->ip_proof->n; i++) {
        if (EC_POINT_point2oct(group, proof->ip_proof->vec_R[i], form, p, point_len,
                               bn_ctx) == 0)
            goto end;

        p += point_len;
    }

    if (!BN_bn2bin(proof->ip_proof->a, p))
        goto end;

    p += bn_len;

    if (!BN_bn2bin(proof->ip_proof->b, p))
        goto end;

    p += bn_len;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}

/** Decodes binary to BULLET_PROOF
 *  \param  in         Memory buffer with the encoded BULLET_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return BULLET_PROOF_PUB_PARAM object pointer on success and NULL otherwise
 */
BULLET_PROOF *BULLET_PROOF_decode(unsigned char *in, size_t size)
{
    unsigned char *p;
    int *q = (int *)in, curve_id;
    size_t point_len, bn_len, proof_len, ip_proof_len, n, i;
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
    BULLET_PROOF *proof = NULL;
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

    n = (size_t)n2l(*q);
    q++;
    p = (unsigned char *)q;

    order = EC_GROUP_get0_order(group);
    bn_len = BN_num_bytes(order);

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    /* len(curve_id) + len(n) + len(V[n]+A+S+T1+T2) + len(taux+mu+tx) */
    proof_len = 4 + 4 + point_len * (n + 4) + bn_len * 3;
    if (size < proof_len) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    proof = bullet_proof_alloc(group);
    if (proof == NULL)
        goto err;

    if (!(proof->V = OPENSSL_zalloc(n * sizeof(*proof->V)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (i = 0; i < n; i++) {
        if (!(proof->V[i] = EC_POINT_new(group)))
            goto err;

        if (!EC_POINT_oct2point(group, proof->V[i], p, point_len, bn_ctx))
            goto err;

        p += point_len;
    }

    proof->n = (size_t)n;

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

    q = (int *)p;
    n = (size_t)n2l(*q);
    q++;
    p = (unsigned char *)q;

    /* ip_proof_len = len(n) + len(vec_L[n]+vec_R[n]) + len(a+b) */
    ip_proof_len = 4 + point_len * n * 2 + bn_len * 2;
    if (size < (proof_len + ip_proof_len)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    if (!(ip_proof = bp_inner_product_proof_alloc(n)))
        goto err;

    for (i = 0; i < n; i++) {
        if (!(ip_proof->vec_L[i] = EC_POINT_new(group)))
            goto err;

        if (!EC_POINT_oct2point(group, ip_proof->vec_L[i], p, point_len, bn_ctx))
            goto err;

        p += point_len;
    }

    for (i = 0; i < n; i++) {
        if (!(ip_proof->vec_R[i] = EC_POINT_new(group)))
            goto err;

        if (!EC_POINT_oct2point(group, ip_proof->vec_R[i], p, point_len, bn_ctx))
            goto err;

        p += point_len;
    }

    ip_proof->n = (size_t)n;

    if (!BN_bin2bn(p, (int)bn_len, ip_proof->a))
        goto err;

    p += bn_len;

    if (!BN_bin2bn(p, (int)bn_len, ip_proof->b))
        goto err;

    p += bn_len;

    proof->ip_proof = ip_proof;

    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return proof;

err:
    bp_inner_product_proof_free(ip_proof);
    BULLET_PROOF_free(proof);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return NULL;
}
