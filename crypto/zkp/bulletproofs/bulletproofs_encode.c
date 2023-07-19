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
#include <crypto/zkp/common/zkp_util.h>
#include "internal/endian.h"
#include "bulletproofs.h"
#include "range_proof.h"
#include "r1cs.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)
DEFINE_STACK_OF(BP_VARIABLE)

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

            if (V->name != NULL) {
                size += strlen(V->name);
            }

            size += 1;
        }

        return size;
    }

    q = (int *)out;
    *q++ = zkp_l2n((int)n);
    p = (unsigned char *)q;

    for (i = 0; i < n; i++) {
        V = sk_BP_VARIABLE_value(sk, i);
        if (V == NULL)
            goto end;

        if (EC_POINT_point2oct(group, V->point, form, p, point_len, bn_ctx) == 0)
            goto end;

        p += point_len;

        if (V->name == NULL) {
            *p++ = '\0';
            continue;
        }

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
    n = (int)zkp_n2l(*q);
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
        if (*name == '\0') {
            name = NULL;
        } else {
            p += strlen(name);
        }

        p += 1;

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

static int bp_inner_product_proof_encode(bp_inner_product_proof_t *ip_proof,
                                         unsigned char *out, const EC_GROUP *group,
                                         BN_CTX *bn_ctx)
{
    int bn_len, sk_len, len;
    unsigned char *p = out;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (ip_proof == NULL || group == NULL || bn_ctx == NULL)
        return 0;

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    sk_bn = sk_BIGNUM_new_reserve(NULL, 2);
    if (sk_bn == NULL)
        goto end;

    if (sk_BIGNUM_push(sk_bn, ip_proof->a) <= 0
        || sk_BIGNUM_push(sk_bn, ip_proof->b) <= 0)
        goto end;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, NULL, bn_len);
    if (sk_len == 0)
        goto end;

    len = sk_len;

    sk_len = zkp_stack_of_point_encode(ip_proof->sk_L, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;

    len += sk_len;

    sk_len = zkp_stack_of_point_encode(ip_proof->sk_R, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;

    len += sk_len;

    if (out == NULL)
        return len;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, p, bn_len);
    if (sk_len == 0)
        goto end;

    p += sk_len;

    sk_len = zkp_stack_of_point_encode(ip_proof->sk_L, p, group, bn_ctx);
    if (sk_len == 0)
        goto end;

    p += sk_len;

    sk_len = zkp_stack_of_point_encode(ip_proof->sk_R, p, group, bn_ctx);
    if (sk_len == 0)
        goto end;

    p += sk_len;

end:
    sk_BIGNUM_free(sk_bn);
    return p != NULL ? p - out : 0;
}

static bp_inner_product_proof_t *bp_inner_product_proof_decode(const unsigned char *in,
                                                               int *len,
                                                               const EC_GROUP *group,
                                                               BN_CTX *bn_ctx)
{
    int bn_len, sk_len;
    unsigned char *p = (unsigned char *)in;
    STACK_OF(BIGNUM) *sk_bn = NULL;
    bp_inner_product_proof_t *ip_proof = NULL;

    if (in == NULL || group == NULL || bn_ctx == NULL)
        return NULL;

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    if (!(ip_proof = bp_inner_product_proof_alloc(1)))
        goto err;

    sk_EC_POINT_free(ip_proof->sk_L);
    sk_EC_POINT_free(ip_proof->sk_R);
    ip_proof->sk_L = NULL;
    ip_proof->sk_R = NULL;

    if (!(sk_bn = zkp_stack_of_bignum_decode(p, &sk_len, bn_len)))
        goto err;

    if (sk_BIGNUM_num(sk_bn) != 2)
        goto err;

    if (!BN_copy(ip_proof->a, sk_BIGNUM_value(sk_bn, 0))
        || !BN_copy(ip_proof->b, sk_BIGNUM_value(sk_bn, 1)))
        goto err;

    p += sk_len;

    if (!(ip_proof->sk_L = zkp_stack_of_point_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    if (!(ip_proof->sk_R = zkp_stack_of_point_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    if (len != NULL)
        *len = p - in;

    sk_BIGNUM_free(sk_bn);
    return ip_proof;

err:
    sk_BIGNUM_pop_free(sk_bn, BN_free);
    bp_inner_product_proof_free(ip_proof);
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

    sk_len = zkp_stack_of_point_encode(pp->sk_G, NULL, group, bn_ctx);
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
    *q++ = zkp_l2n((int)curve_id);
    *q++ = zkp_l2n((int)pp->gens_capacity);
    *q++ = zkp_l2n((int)pp->party_capacity);
    p = (unsigned char *)q;

    if (EC_POINT_point2oct(group, pp->H, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(group, pp->U, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    sk_len = zkp_stack_of_point_encode(pp->sk_G, p, group, bn_ctx);
    if (sk_len == 0)
        goto end;

    p += sk_len;

    sk_len = zkp_stack_of_point_encode(pp->sk_H, p, group, bn_ctx);
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

    curve_id = zkp_n2l(*q);
    q++;
    gens_capacity = (size_t)zkp_n2l(*q);
    q++;
    party_capacity = (size_t)zkp_n2l(*q);
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

    if (!(pp->sk_G = zkp_stack_of_point_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    if (!(pp->sk_H = zkp_stack_of_point_decode(p, &sk_len, group, bn_ctx)))
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

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

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

    if (!(sk_len = zkp_stack_of_bignum_encode(witness->sk_r, NULL, bn_len)))
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
    *q++ = zkp_l2n((int)curve_id);
    p = (unsigned char *)q;

    if (EC_POINT_point2oct(group, witness->H, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (!(sk_len = bp_stack_of_variable_encode(witness->sk_V, p, group, bn_ctx)))
        goto end;

    p += sk_len;

    if (flag == 1) {
        if (!(sk_len = zkp_stack_of_bignum_encode(witness->sk_r, p, bn_len)))
            goto end;

        p += sk_len;

        if (!(sk_len = zkp_stack_of_bignum_encode(witness->sk_v, p, bn_len)))
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
 *  \param  flag       The flag is an indicator for decoding random number 'r'
 *                     and plaintext 'v', with 1 indicating decoding and 0
 *                     indicating no decoding.
 *  \return BP_WITNESS object pointer on success and NULL otherwise
 */
BP_WITNESS *BP_WITNESS_decode(const unsigned char *in, size_t size, int flag)
{
    unsigned char *p;
    int curve_id, *q = (int *)in, bn_len, sk_len;
    size_t point_len;
    BP_WITNESS *witness = NULL;
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

    curve_id = zkp_n2l(*q);
    q++;
    p = (unsigned char *)q;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        goto err;
    }

    if (!(witness->H = EC_POINT_new(group)))
        goto err;

    if (!EC_POINT_oct2point(group, witness->H, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!(witness->sk_V = bp_stack_of_variable_decode(p, &sk_len, group, bn_ctx)))
        goto err;

    p += sk_len;

    if (flag == 1) {
        if (!(witness->sk_r = zkp_stack_of_bignum_decode(p, &sk_len, bn_len)))
            goto err;

        p += sk_len;

        if (!(witness->sk_v = zkp_stack_of_bignum_decode(p, &sk_len, bn_len)))
            goto err;

        p += sk_len;
    }

    witness->group = group;

    witness->references = 1;
    if ((witness->lock = CRYPTO_THREAD_lock_new()) == NULL)
        goto err;

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
    size_t len;
    unsigned char *p = NULL;
    bp_inner_product_proof_t *ip_proof;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    sk_point = sk_EC_POINT_new_reserve(NULL, 4);
    sk_bn = sk_BIGNUM_new_reserve(NULL, 3);
    if (sk_point == NULL || sk_bn == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return 0;
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

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));
    len = sizeof(int);

    if (sk_EC_POINT_push(sk_point, proof->A) <= 0
        || sk_EC_POINT_push(sk_point, proof->S) <= 0
        || sk_EC_POINT_push(sk_point, proof->T1) <= 0
        || sk_EC_POINT_push(sk_point, proof->T2) <= 0)
        goto end;

    sk_len = zkp_stack_of_point_encode(sk_point, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    if (sk_BIGNUM_push(sk_bn, proof->taux) <= 0
        || sk_BIGNUM_push(sk_bn, proof->mu) <= 0
        || sk_BIGNUM_push(sk_bn, proof->tx) <= 0)
        goto end;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, NULL, bn_len);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    sk_len = bp_inner_product_proof_encode(ip_proof, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    /* encoding proof */
    q = (int *)out;
    *q++ = zkp_l2n(curve_id);
    p = (unsigned char *)q;

    sk_len = zkp_stack_of_point_encode(sk_point, p, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    p += sk_len;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, p, bn_len);
    if (sk_len == 0)
        goto end;
    p += sk_len;

    /* encoding ip_proof */
    len = bp_inner_product_proof_encode(ip_proof, p, group, bn_ctx);
    if (len == 0)
        goto end;
    p += len;

    ret = p - out;
end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    return ret;
}

/** Decodes binary to BP_RANGE_PROOF
 *  \param  in         Memory buffer with the encoded BP_RANGE_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_RANGE_PROOF object pointer on success and NULL otherwise
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_decode(const unsigned char *in, size_t size)
{
    unsigned char *p;
    int *q = (int *)in, curve_id, len;
    size_t point_len, bn_len, proof_len;
    BP_RANGE_PROOF *proof = NULL;
    bp_inner_product_proof_t *ip_proof = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (in == NULL || size <= 8) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    curve_id = zkp_n2l(*q);
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

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    /* len(curve_id) + len(A+S+T1+T2) + len(taux+mu+tx) + len(a+b) */
    proof_len = 4 + point_len * 4 + bn_len * 3 + bn_len * 2;
    if (size < proof_len) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL)
        goto err;

    proof->references = 1;
    if ((proof->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    sk_point = zkp_stack_of_point_decode(p, &len, group, bn_ctx);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_EC_POINT_num(sk_point) < 4)
        goto err;

    proof->A = sk_EC_POINT_value(sk_point, 0);
    proof->S = sk_EC_POINT_value(sk_point, 1);
    proof->T1 = sk_EC_POINT_value(sk_point, 2);
    proof->T2 = sk_EC_POINT_value(sk_point, 3);

    sk_bn = zkp_stack_of_bignum_decode(p, &len, bn_len);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_BIGNUM_num(sk_bn) < 3)
        goto err;

    proof->taux = sk_BIGNUM_value(sk_bn, 0);
    proof->mu = sk_BIGNUM_value(sk_bn, 1);
    proof->tx = sk_BIGNUM_value(sk_bn, 2);

    ip_proof = bp_inner_product_proof_decode(p, &len, group, bn_ctx);
    if (ip_proof == NULL)
        goto err;
    p += len;

    proof->ip_proof = ip_proof;

    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return proof;

err:
    sk_BIGNUM_pop_free(sk_bn, BN_free);
    sk_EC_POINT_pop_free(sk_point, EC_POINT_free);
    bp_inner_product_proof_free(ip_proof);
    OPENSSL_free(proof);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return NULL;
}

/** Encodes BP_R1CS_PROOF to binary
 *  \param  proof      BP_R1CS_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_R1CS_PROOF_encode(const BP_R1CS_PROOF *proof, unsigned char *out,
                            size_t size)
{
    int *q, curve_id, bn_len, ret = 0, sk_len;
    size_t len;
    unsigned char *p = NULL;
    bp_inner_product_proof_t *ip_proof;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    sk_point = sk_EC_POINT_new_reserve(NULL, 11);
    sk_bn = sk_BIGNUM_new_reserve(NULL, 3);
    if (sk_point == NULL || sk_bn == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ip_proof = proof->ip_proof;

    if ((curve_id = EC_POINT_get_curve_name(proof->AI1)) == NID_undef
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

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));
    len = sizeof(int);

    if (sk_EC_POINT_push(sk_point, proof->AI1) <= 0
        || sk_EC_POINT_push(sk_point, proof->AO1) <= 0
        || sk_EC_POINT_push(sk_point, proof->S1) <= 0
        || sk_EC_POINT_push(sk_point, proof->T1) <= 0
        || sk_EC_POINT_push(sk_point, proof->T3) <= 0
        || sk_EC_POINT_push(sk_point, proof->T4) <= 0
        || sk_EC_POINT_push(sk_point, proof->T5) <= 0
        || sk_EC_POINT_push(sk_point, proof->T6) <= 0
#if 0
        || sk_EC_POINT_push(sk_point, proof->AI2) <= 0
        || sk_EC_POINT_push(sk_point, proof->AO2) <= 0
        || sk_EC_POINT_push(sk_point, proof->S2) <= 0
#endif
       )
        goto end;

    sk_len = zkp_stack_of_point_encode(sk_point, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    if (sk_BIGNUM_push(sk_bn, proof->taux) <= 0
        || sk_BIGNUM_push(sk_bn, proof->mu) <= 0
        || sk_BIGNUM_push(sk_bn, proof->tx) <= 0)
        goto end;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, NULL, bn_len);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    sk_len = bp_inner_product_proof_encode(ip_proof, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    /* encoding proof */
    q = (int *)out;
    *q++ = zkp_l2n(curve_id);
    p = (unsigned char *)q;

    sk_len = zkp_stack_of_point_encode(sk_point, p, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    p += sk_len;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, p, bn_len);
    if (sk_len == 0)
        goto end;
    p += sk_len;

    /* encoding ip_proof */
    sk_len = bp_inner_product_proof_encode(ip_proof, p, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    p += sk_len;

    ret = p - out;
end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    return ret;
}

/** Decodes binary to BP_R1CS_PROOF
 *  \param  in         Memory buffer with the encoded BP_R1CS_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_R1CS_PROOF object pointer on success and NULL otherwise
 */
BP_R1CS_PROOF *BP_R1CS_PROOF_decode(const unsigned char *in, size_t size)
{
    unsigned char *p;
    int *q = (int *)in, curve_id, len;
    size_t point_len, bn_len, proof_len;
    BP_R1CS_PROOF *proof = NULL;
    bp_inner_product_proof_t *ip_proof = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;


    if (in == NULL || size <= 8) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    curve_id = zkp_n2l(*q);
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

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

#if 1
    proof_len = 4 + point_len * 8 + bn_len * 3 + bn_len * 2;
#else
    proof_len = 4 + point_len * 11 + bn_len * 3 + bn_len * 2;
#endif
    if (size < proof_len) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL)
        goto err;

    proof->references = 1;
    if ((proof->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    sk_point = zkp_stack_of_point_decode(p, &len, group, bn_ctx);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_EC_POINT_num(sk_point) < 8)
        goto err;

    proof->AI1 = sk_EC_POINT_value(sk_point, 0);
    proof->AO1 = sk_EC_POINT_value(sk_point, 1);
    proof->S1 = sk_EC_POINT_value(sk_point, 2);
    proof->T1 = sk_EC_POINT_value(sk_point, 3);
    proof->T3 = sk_EC_POINT_value(sk_point, 4);
    proof->T4 = sk_EC_POINT_value(sk_point, 5);
    proof->T5 = sk_EC_POINT_value(sk_point, 6);
    proof->T6 = sk_EC_POINT_value(sk_point, 7);
#if 1
    proof->AI2 = EC_POINT_new(group);
    proof->AO2 = EC_POINT_new(group);
    proof->S2 = EC_POINT_new(group);
    if (proof->AI2 == NULL || proof->AO2 == NULL || proof->S2 == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    EC_POINT_set_to_infinity(group, proof->AI2);
    EC_POINT_set_to_infinity(group, proof->AO2);
    EC_POINT_set_to_infinity(group, proof->S2);
#else
    proof->AI2 = sk_EC_POINT_value(sk_point, 8);
    proof->AO2 = sk_EC_POINT_value(sk_point, 9);
    proof->S2 = sk_EC_POINT_value(sk_point, 10);
#endif

    sk_bn = zkp_stack_of_bignum_decode(p, &len, bn_len);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_BIGNUM_num(sk_bn) < 3)
        goto err;

    proof->taux = sk_BIGNUM_value(sk_bn, 0);
    proof->mu = sk_BIGNUM_value(sk_bn, 1);
    proof->tx = sk_BIGNUM_value(sk_bn, 2);

    ip_proof = bp_inner_product_proof_decode(p, &len, group, bn_ctx);
    if (ip_proof == NULL)
        goto err;
    p += len;

    proof->ip_proof = ip_proof;

    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return proof;

err:
    sk_BIGNUM_pop_free(sk_bn, BN_free);
    sk_EC_POINT_pop_free(sk_point, EC_POINT_free);
    bp_inner_product_proof_free(ip_proof);
    BP_R1CS_PROOF_free(proof);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return NULL;
}
