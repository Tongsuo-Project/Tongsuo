/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include "internal/endian.h"
#include <crypto/zkp/common/zkp_util.h>
#include "nizk.h"
#include "nizk_plaintext_knowledge.h"
#include "nizk_plaintext_equality.h"
#include "nizk_dlog_knowledge.h"
#include "nizk_dlog_equality.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)

static point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;

/** Encodes NIZK_PUB_PARAM to binary
 *  \param  pp         NIZK_PUB_PARAM object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t NIZK_PUB_PARAM_encode(const NIZK_PUB_PARAM *pp, unsigned char *out, size_t size)
{
    int *q, curve_id;
    size_t point_len, ret = 0, len;
    unsigned char *p;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    group = pp->group;

    curve_id = EC_GROUP_get_curve_name(group);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);

    len = sizeof(int) + point_len * 2;
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

    if (EC_POINT_point2oct(group, pp->G, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(group, pp->H, form, p, point_len, bn_ctx) == 0)
        goto end;

    p += point_len;

    ret = p - out;

end:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Decodes binary to NIZK_PUB_PARAM
 *  \param  in         Memory buffer with the encoded NIZK_PUB_PARAM
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return NIZK_PUB_PARAM object pointer on success and NULL otherwise
 */
NIZK_PUB_PARAM *NIZK_PUB_PARAM_decode(const unsigned char *in, size_t size)
{
    unsigned char *p;
    int curve_id, *q = (int *)in;
    size_t point_len;
    NIZK_PUB_PARAM *pp = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *G = NULL, *H = NULL;

    if (in == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    curve_id = zkp_n2l(*q);
    q++;
    p = (unsigned char *)q;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    if (size < (sizeof(int) + point_len * 2)) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    G = EC_POINT_new(group);
    H = EC_POINT_new(group);
    if (G == NULL || H == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_oct2point(group, G, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!EC_POINT_oct2point(group, H, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    pp = NIZK_PUB_PARAM_new(group, G, H);
    if (pp == NULL)
        goto err;

    EC_POINT_free(G);
    EC_POINT_free(H);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return pp;

err:
    EC_POINT_free(G);
    EC_POINT_free(H);
    EC_GROUP_free(group);
    NIZK_PUB_PARAM_free(pp);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Encodes NIZK_WITNESS to binary
 *  \param  pp         NIZK_WITNESS object
 *  \param  out        The buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  flag       The flag is an indicator for encoding random number 'r'
 *                     and plaintext 'v', with 1 indicating encoding and 0
 *                     indicating no encoding.
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t NIZK_WITNESS_encode(const NIZK_WITNESS *witness, unsigned char *out,
                           size_t size, int flag)
{
    int *q, bn_len;
    size_t ret = 0, len;
    unsigned char *p;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (witness == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_len = BN_num_bytes(witness->order);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    len = sizeof(int) + bn_len * 2;

    if (flag == 1)
        len += bn_len;

    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    q = (int *)out;
    *q++ = zkp_l2n((int)bn_len);
    p = (unsigned char *)q;

    len = zkp_bignum_encode(witness->order, p, bn_len);
    if (len <= 0)
        goto end;

    p += len;

    len = zkp_bignum_encode(witness->r, p, bn_len);
    if (len <= 0)
        goto end;

    p += len;

    if (flag == 1) {
        len = zkp_bignum_encode(witness->v, p, bn_len);
        if (len <= 0)
            goto end;

        p += len;
    }

    ret = p - out;

end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}

/** Decodes binary to NIZK_WITNESS
 *  \param  in         Memory buffer with the encoded NIZK_WITNESS
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \param  flag       The flag is an indicator for decoding random number 'r'
 *                     and plaintext 'v', with 1 indicating decoding and 0
 *                     indicating no decoding.
 *  \return NIZK_WITNESS object pointer on success and NULL otherwise
 */
NIZK_WITNESS *NIZK_WITNESS_decode(const unsigned char *in, size_t size, int flag)
{
    unsigned char *p;
    int *q = (int *)in, bn_len;
    NIZK_WITNESS *witness = NULL;

    if (in == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    bn_len = zkp_n2l(*q);
    q++;
    p = (unsigned char *)q;

    if (size < (sizeof(int) + bn_len * 2)) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        goto err;
    }

    witness->order = zkp_bignum_decode(p, NULL, bn_len);
    if (witness->order == NULL) {
        goto err;
    }

    p += bn_len;

    witness->r = zkp_bignum_decode(p, NULL, bn_len);
    if (witness->r == NULL) {
        goto err;
    }

    p += bn_len;

    if (flag == 1) {
        if (size < (sizeof(int) + bn_len * 3)) {
            ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
            return NULL;
        }

        witness->v = zkp_bignum_decode(p, NULL, bn_len);
        if (witness->v == NULL) {
            goto err;
        }
    }

    witness->references = 1;
    if ((witness->lock = CRYPTO_THREAD_lock_new()) == NULL)
        goto err;

    return witness;

err:
    NIZK_WITNESS_free(witness);
    return NULL;
}

/** Encodes NIZK_PLAINTEXT_KNOWLEDGE_PROOF to binary
 *  \param  proof      NIZK_PLAINTEXT_KNOWLEDGE_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t NIZK_PLAINTEXT_KNOWLEDGE_PROOF_encode(const NIZK_PLAINTEXT_KNOWLEDGE_PROOF *proof,
                                             unsigned char *out, size_t size)
{
    int *q, curve_id, bn_len, ret = 0, sk_len;
    size_t len;
    unsigned char *p = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    sk_point = sk_EC_POINT_new_reserve(NULL, 2);
    sk_bn = sk_BIGNUM_new_reserve(NULL, 2);
    if (sk_point == NULL || sk_bn == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if ((curve_id = EC_POINT_get_curve_name(proof->A)) == NID_undef) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));
    len = sizeof(int);

    if (sk_EC_POINT_push(sk_point, proof->A) <= 0
        || sk_EC_POINT_push(sk_point, proof->B) <= 0)
        goto end;

    sk_len = zkp_stack_of_point_encode(sk_point, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    if (sk_BIGNUM_push(sk_bn, proof->z1) <= 0
        || sk_BIGNUM_push(sk_bn, proof->z2) <= 0)
        goto end;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, NULL, bn_len);
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

    ret = p - out;
end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    return ret;
}

/** Decodes binary to NIZK_PLAINTEXT_KNOWLEDGE_PROOF
 *  \param  in         Memory buffer with the encoded NIZK_PLAINTEXT_KNOWLEDGE_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return NIZK_RANGE_PROOF object pointer on success and NULL otherwise
 */
NIZK_PLAINTEXT_KNOWLEDGE_PROOF *NIZK_PLAINTEXT_KNOWLEDGE_PROOF_decode(const unsigned char *in,
                                                                      size_t size)
{
    unsigned char *p;
    int *q = (int *)in, curve_id, len;
    size_t point_len, bn_len, proof_len;
    NIZK_PLAINTEXT_KNOWLEDGE_PROOF *proof = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (in == NULL || size <= 4) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    curve_id = zkp_n2l(*q);
    q++;

    if (curve_id <= 0) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    p = (unsigned char *)q;

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    /* len(curve_id) + len(A+B) + len(z1+z2) */
    proof_len = 4 + point_len * 2 + bn_len * 2;
    if (size < proof_len) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL)
        goto err;

    sk_point = zkp_stack_of_point_decode(p, &len, group, bn_ctx);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_EC_POINT_num(sk_point) < 2)
        goto err;

    proof->A = sk_EC_POINT_value(sk_point, 0);
    proof->B = sk_EC_POINT_value(sk_point, 1);

    sk_bn = zkp_stack_of_bignum_decode(p, &len, bn_len);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_BIGNUM_num(sk_bn) < 2)
        goto err;

    proof->z1 = sk_BIGNUM_value(sk_bn, 0);
    proof->z2 = sk_BIGNUM_value(sk_bn, 1);

    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return proof;

err:
    sk_BIGNUM_pop_free(sk_bn, BN_free);
    sk_EC_POINT_pop_free(sk_point, EC_POINT_free);
    OPENSSL_free(proof);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return NULL;
}

/** Encodes NIZK_PLAINTEXT_EQUALITY_PROOF to binary
 *  \param  proof      NIZK_PLAINTEXT_EQUALITY_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t NIZK_PLAINTEXT_EQUALITY_PROOF_encode(const NIZK_PLAINTEXT_EQUALITY_PROOF *proof,
                                            unsigned char *out, size_t size)
{
    int *q, curve_id, bn_len, ret = 0, sk_len;
    size_t len;
    unsigned char *p = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    sk_point = sk_EC_POINT_dup(proof->sk_A);
    sk_bn = sk_BIGNUM_new_reserve(NULL, 2);
    if (sk_point == NULL || sk_bn == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if ((curve_id = EC_POINT_get_curve_name(proof->B)) == NID_undef) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));
    len = sizeof(int);

    if (sk_EC_POINT_push(sk_point, proof->B) <= 0)
        goto end;

    sk_len = zkp_stack_of_point_encode(sk_point, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    if (sk_BIGNUM_push(sk_bn, proof->z) <= 0
        || sk_BIGNUM_push(sk_bn, proof->t) <= 0)
        goto end;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, NULL, bn_len);
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

    ret = p - out;
end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    return ret;
}

/** Decodes binary to NIZK_PLAINTEXT_EQUALITY_PROOF
 *  \param  in         Memory buffer with the encoded NIZK_PLAINTEXT_EQUALITY_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return NIZK_RANGE_PROOF object pointer on success and NULL otherwise
 */
NIZK_PLAINTEXT_EQUALITY_PROOF *NIZK_PLAINTEXT_EQUALITY_PROOF_decode(const unsigned char *in,
                                                                    size_t size)
{
    unsigned char *p;
    int *q = (int *)in, curve_id, len;
    size_t point_len, bn_len, proof_len;
    NIZK_PLAINTEXT_EQUALITY_PROOF *proof = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (in == NULL || size <= 4) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    curve_id = zkp_n2l(*q);
    q++;

    if (curve_id <= 0) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    p = (unsigned char *)q;

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    /* len(curve_id) + len(sk_A+B) + len(z1+z2) */
    proof_len = 4 + point_len + bn_len * 2;
    if (size < proof_len) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL)
        goto err;

    sk_point = zkp_stack_of_point_decode(p, &len, group, bn_ctx);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_EC_POINT_num(sk_point) < 1)
        goto err;

    proof->sk_A = sk_point;
    proof->B = sk_EC_POINT_pop(sk_point);

    sk_bn = zkp_stack_of_bignum_decode(p, &len, bn_len);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_BIGNUM_num(sk_bn) < 2)
        goto err;

    proof->z = sk_BIGNUM_value(sk_bn, 0);
    proof->t = sk_BIGNUM_value(sk_bn, 1);

    sk_BIGNUM_free(sk_bn);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return proof;

err:
    sk_BIGNUM_pop_free(sk_bn, BN_free);
    sk_EC_POINT_pop_free(sk_point, EC_POINT_free);
    OPENSSL_free(proof);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return NULL;
}

/** Encodes NIZK_DLOG_KNOWLEDGE_PROOF to binary
 *  \param  proof      NIZK_DLOG_KNOWLEDGE_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t NIZK_DLOG_KNOWLEDGE_PROOF_encode(const NIZK_DLOG_KNOWLEDGE_PROOF *proof,
                                        unsigned char *out, size_t size)
{
    int *q, curve_id, bn_len, ret = 0, sk_len;
    size_t len;
    unsigned char *p = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    sk_point = sk_EC_POINT_new_reserve(NULL, 1);
    sk_bn = sk_BIGNUM_new_reserve(NULL, 1);
    if (sk_point == NULL || sk_bn == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if ((curve_id = EC_POINT_get_curve_name(proof->A)) == NID_undef) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));
    len = sizeof(int);

    if (sk_EC_POINT_push(sk_point, proof->A) <= 0)
        goto end;

    sk_len = zkp_stack_of_point_encode(sk_point, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    if (sk_BIGNUM_push(sk_bn, proof->z) <= 0)
        goto end;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, NULL, bn_len);
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

    ret = p - out;
end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    return ret;
}

/** Decodes binary to NIZK_DLOG_KNOWLEDGE_PROOF
 *  \param  in         Memory buffer with the encoded NIZK_DLOG_KNOWLEDGE_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return NIZK_RANGE_PROOF object pointer on success and NULL otherwise
 */
NIZK_DLOG_KNOWLEDGE_PROOF *NIZK_DLOG_KNOWLEDGE_PROOF_decode(const unsigned char *in,
                                                            size_t size)
{
    unsigned char *p;
    int *q = (int *)in, curve_id, len;
    size_t point_len, bn_len, proof_len;
    NIZK_DLOG_KNOWLEDGE_PROOF *proof = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (in == NULL || size <= 4) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    curve_id = zkp_n2l(*q);
    q++;

    if (curve_id <= 0) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    p = (unsigned char *)q;

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    /* len(curve_id) + len(A) + len(z) */
    proof_len = 4 + point_len + bn_len;
    if (size < proof_len) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL)
        goto err;

    sk_point = zkp_stack_of_point_decode(p, &len, group, bn_ctx);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_EC_POINT_num(sk_point) < 1)
        goto err;

    proof->A = sk_EC_POINT_value(sk_point, 0);

    sk_bn = zkp_stack_of_bignum_decode(p, &len, bn_len);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_BIGNUM_num(sk_bn) < 1)
        goto err;

    proof->z = sk_BIGNUM_value(sk_bn, 0);

    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return proof;

err:
    sk_BIGNUM_pop_free(sk_bn, BN_free);
    sk_EC_POINT_pop_free(sk_point, EC_POINT_free);
    OPENSSL_free(proof);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return NULL;
}

/** Encodes NIZK_DLOG_EQUALITY_PROOF to binary
 *  \param  proof      NIZK_DLOG_EQUALITY_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t NIZK_DLOG_EQUALITY_PROOF_encode(const NIZK_DLOG_EQUALITY_PROOF *proof,
                                       unsigned char *out, size_t size)
{
    int *q, curve_id, bn_len, ret = 0, sk_len;
    size_t len;
    unsigned char *p = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    sk_point = sk_EC_POINT_new_reserve(NULL, 2);
    sk_bn = sk_BIGNUM_new_reserve(NULL, 1);
    if (sk_point == NULL || sk_bn == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if ((curve_id = EC_POINT_get_curve_name(proof->A1)) == NID_undef) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));
    len = sizeof(int);

    if (sk_EC_POINT_push(sk_point, proof->A1) <= 0
        || sk_EC_POINT_push(sk_point, proof->A2) <= 0)
        goto end;

    sk_len = zkp_stack_of_point_encode(sk_point, NULL, group, bn_ctx);
    if (sk_len == 0)
        goto end;
    len += sk_len;

    if (sk_BIGNUM_push(sk_bn, proof->z) <= 0)
        goto end;

    sk_len = zkp_stack_of_bignum_encode(sk_bn, NULL, bn_len);
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

    ret = p - out;
end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    return ret;
}

/** Decodes binary to NIZK_DLOG_EQUALITY_PROOF
 *  \param  in         Memory buffer with the encoded NIZK_DLOG_EQUALITY_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return NIZK_RANGE_PROOF object pointer on success and NULL otherwise
 */
NIZK_DLOG_EQUALITY_PROOF *NIZK_DLOG_EQUALITY_PROOF_decode(const unsigned char *in,
                                                          size_t size)
{
    unsigned char *p;
    int *q = (int *)in, curve_id, len;
    size_t point_len, bn_len, proof_len;
    NIZK_DLOG_EQUALITY_PROOF *proof = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    STACK_OF(EC_POINT) *sk_point = NULL;
    STACK_OF(BIGNUM) *sk_bn = NULL;

    if (in == NULL || size <= 4) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    curve_id = zkp_n2l(*q);
    q++;

    if (curve_id <= 0) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    p = (unsigned char *)q;

    bn_len = BN_num_bytes(EC_GROUP_get0_order(group));

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   form, NULL, 0, bn_ctx);
    if (point_len <= 0)
        goto err;

    /* len(curve_id) + len(A1+A2) + len(z) */
    proof_len = 4 + point_len*2 + bn_len;
    if (size < proof_len) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL)
        goto err;

    sk_point = zkp_stack_of_point_decode(p, &len, group, bn_ctx);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_EC_POINT_num(sk_point) < 2)
        goto err;

    proof->A1 = sk_EC_POINT_value(sk_point, 0);
    proof->A2 = sk_EC_POINT_value(sk_point, 1);

    sk_bn = zkp_stack_of_bignum_decode(p, &len, bn_len);
    if (sk_point == NULL)
        goto err;
    p += len;

    if (sk_BIGNUM_num(sk_bn) < 1)
        goto err;

    proof->z = sk_BIGNUM_value(sk_bn, 0);

    sk_BIGNUM_free(sk_bn);
    sk_EC_POINT_free(sk_point);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return proof;

err:
    sk_BIGNUM_pop_free(sk_bn, BN_free);
    sk_EC_POINT_pop_free(sk_point, EC_POINT_free);
    OPENSSL_free(proof);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return NULL;
}
