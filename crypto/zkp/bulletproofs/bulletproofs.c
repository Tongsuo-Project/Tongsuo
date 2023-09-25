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
#include <crypto/zkp/common/zkp_util.h>
#include "bulletproofs.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)
DEFINE_STACK_OF(BP_VARIABLE)

/** Creates a new BP_PUB_PARAM object
 *  \param  group           underlying EC_GROUP object
 *  \param  gens_capacity   the number of generators to precompute for each party.
 *                          For range_proof, it is the maximum bitsize of the
 *                          range_proof, maximum value is 64. For r1cs_proof,
 *                          the capacity must be greater than the number of
 *                          multipliers, rounded up to the next power of two.
 *  \param  party_capacity  the maximum number of parties that can produce on
 *                          aggregated proof. For r1cs_proof, set to 1.
 *  \return newly created BP_PUB_PARAM object or NULL in case of an error
 */
BP_PUB_PARAM *BP_PUB_PARAM_new(const EC_GROUP *group, int gens_capacity,
                               int party_capacity)
{
    int i, n;
    size_t plen;
    unsigned char *pstr = NULL;
    BN_CTX *bn_ctx = NULL;
    const EC_POINT *G = NULL;
    EC_POINT *P = NULL;
    BP_PUB_PARAM *pp = NULL;
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;

    if (group == NULL || gens_capacity <= 0 || party_capacity <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (gens_capacity > BULLET_PROOF_MAX_GENS_CAPACITY) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_GENS_CAPACITY);
        return NULL;
    }

    if (party_capacity > BULLET_PROOF_MAX_PARTY_CAPACITY) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_PARTY_CAPACITY);
        return NULL;
    }

    pp = OPENSSL_zalloc(sizeof(*pp));
    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(pp->group = EC_GROUP_dup(group)))
        goto err;

    G = EC_GROUP_get0_generator(group);

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto err;

    pp->H = EC_POINT_new(group);
    if (pp->H == NULL)
        goto err;

    plen = EC_POINT_point2oct(group, G, format, NULL, 0, bn_ctx);
    if (plen <= 0)
        goto err;

    pstr = OPENSSL_zalloc(plen);
    if (pstr == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EC_POINT_point2oct(group, G, format, pstr, plen, bn_ctx) <= 0)
        goto err;

    if (!zkp_str2point(group, pstr, plen, pp->H, bn_ctx))
        goto err;

    if (!(pp->U = zkp_random_ec_point_new(group, bn_ctx)))
        goto err;

    pp->gens_capacity = gens_capacity;
    pp->party_capacity = party_capacity;
    n = gens_capacity * party_capacity;

    if (!(pp->sk_G = sk_EC_POINT_new_reserve(NULL, n))
        || !(pp->sk_H = sk_EC_POINT_new_reserve(NULL, n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (i = 0; i < n; i++) {
        P = zkp_random_ec_point_new(group, bn_ctx);
        if (P == NULL)
            goto err;

        if (sk_EC_POINT_push(pp->sk_G, P) <= 0)
            goto err;

        P = zkp_random_ec_point_new(group, bn_ctx);
        if (P == NULL)
            goto err;

        if (sk_EC_POINT_push(pp->sk_H, P) <= 0)
            goto err;
    }

    pp->references = 1;
    if ((pp->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    OPENSSL_free(pstr);
    BN_CTX_free(bn_ctx);
    return pp;

err:
    EC_POINT_free(P);
    OPENSSL_free(pstr);
    BN_CTX_free(bn_ctx);
    BP_PUB_PARAM_free(pp);
    return NULL;
}

/** Creates a new BP_PUB_PARAM object by curve name
 *  \param  curve_name      the elliptic curve name
 *  \param  gens_capacity   the number of generators to precompute for each party.
 *                          For range_proof, it is the maximum bitsize of the
 *                          range_proof, maximum value is 64. For r1cs_proof,
 *                          the capacity must be greater than the number of
 *                          multipliers, rounded up to the next power of two.
 *  \param  party_capacity  the maximum number of parties that can produce on
 *                          aggregated proof. For r1cs_proof, set to 1.
 *  \return newly created BP_PUB_PARAM object or NULL in case of an error
 */
BP_PUB_PARAM *BP_PUB_PARAM_new_by_curve_name(const char *curve_name,
                                             int gens_capacity,
                                             int party_capacity)
{
    int curve_id = ossl_ec_curve_name2nid(curve_name);

    if (curve_id == NID_undef) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    return BP_PUB_PARAM_new_by_curve_id(curve_id, gens_capacity, party_capacity);
}

/** Creates a new BP_PUB_PARAM object by curve id
 *  \param  curve_id        the elliptic curve id
 *  \param  gens_capacity   the number of generators to precompute for each party.
 *                          For range_proof, it is the maximum bitsize of the
 *                          range_proof, maximum value is 64. For r1cs_proof,
 *                          the capacity must be greater than the number of
 *                          multipliers, rounded up to the next power of two.
 *  \param  party_capacity  the maximum number of parties that can produce on
 *                          aggregated proof. For r1cs_proof, set to 1.
 *  \return newly created BP_PUB_PARAM object or NULL in case of an error
 */
BP_PUB_PARAM *BP_PUB_PARAM_new_by_curve_id(int curve_id,
                                           int gens_capacity,
                                           int party_capacity)
{
    BP_PUB_PARAM *ret;
    EC_GROUP *group = NULL;

    if (!(group = EC_GROUP_new_by_curve_name(curve_id)))
        return NULL;

    ret = BP_PUB_PARAM_new(group, gens_capacity, party_capacity);

    EC_GROUP_free(group);

    return ret;
}

/** Frees a BP_PUB_PARAM object
 *  \param  pp        BP_PUB_PARAM object to be freed
 */
void BP_PUB_PARAM_free(BP_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return;

    CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock);
    REF_PRINT_COUNT("BP_PUB_PARAM", pp);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    sk_EC_POINT_pop_free(pp->sk_G, EC_POINT_free);
    sk_EC_POINT_pop_free(pp->sk_H, EC_POINT_free);
    EC_POINT_free(pp->U);
    EC_POINT_free(pp->H);
    EC_GROUP_free(pp->group);
    CRYPTO_THREAD_lock_free(pp->lock);
    OPENSSL_clear_free((void *)pp, sizeof(*pp));
}

/** Increases the internal reference count of a BP_PUB_PARAM object.
 *  \param  pp  BP_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_PUB_PARAM_up_ref(BP_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return 0;

    if (CRYPTO_UP_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BP_PUB_PARAM", pp);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

/** Decreases the internal reference count of a BP_PUB_PARAM object.
 *  \param  pp  BP_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_PUB_PARAM_down_ref(BP_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return 0;

    if (CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BP_PUB_PARAM", pp);
    REF_ASSERT_ISNT(ref < 0);
    return ((ref > 0) ? 1 : 0);
}

/** Creates a new BP_VARIABLE object
 *  \param  name           the bulletproofs variable name, used for indexing.
 *  \param  point          EC_POINT object
 *  \param  group          EC_GROUP object
 *  \return newly created BP_WITNESS object or NULL in case of an error
 */
BP_VARIABLE *BP_VARIABLE_new(const char *name, const EC_POINT *point,
                             const EC_GROUP *group)
{
    BP_VARIABLE *ret = NULL;

    if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->point = EC_POINT_dup(point, group);

    if (name != NULL)
        ret->name = OPENSSL_strdup(name);

    if (ret->point == NULL)
        goto err;

    return ret;
err:
    BP_VARIABLE_free(ret);
    return NULL;
}

/** Frees a BP_VARIABLE object
 *  \param  var   BP_VARIABLE object to be freed
 */
void BP_VARIABLE_free(BP_VARIABLE *var)
{
    if (var == NULL)
        return;

    EC_POINT_free(var->point);
    OPENSSL_free(var->name);
    OPENSSL_free(var);
}

/** Creates a new BP_WITNESS object
 *  \param  pp           underlying BP_PUB_PARAM object
 *  \return newly created BP_WITNESS object or NULL in case of an error
 */
BP_WITNESS *BP_WITNESS_new(const BP_PUB_PARAM *pp)
{
    BP_WITNESS *witness = NULL;

    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(witness->sk_r = sk_BIGNUM_new_null())
        || !(witness->sk_v = sk_BIGNUM_new_null())
        || !(witness->sk_V = sk_BP_VARIABLE_new_null())) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!(witness->group = EC_GROUP_dup(pp->group))
        || !(witness->H = EC_POINT_dup(pp->H, pp->group)))
        goto err;

    witness->references = 1;
    if ((witness->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return witness;
err:
    BP_WITNESS_free(witness);
    return NULL;
}

/** Frees a BP_WITNESS object
 *  \param  witness   BP_WITNESS object to be freed
 */
void BP_WITNESS_free(BP_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return;

    CRYPTO_DOWN_REF(&witness->references, &ref, witness->lock);
    REF_PRINT_COUNT("BP_WITNESS", witness);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    sk_BIGNUM_pop_free(witness->sk_r, BN_free);
    sk_BIGNUM_pop_free(witness->sk_v, BN_free);
    sk_BP_VARIABLE_pop_free(witness->sk_V, BP_VARIABLE_free);
    EC_POINT_free(witness->H);
    EC_GROUP_free(witness->group);
    CRYPTO_THREAD_lock_free(witness->lock);
    OPENSSL_free(witness);
}

/** Increases the internal reference count of a BP_WITNESS object.
 *  \param  witness  BP_WITNESS object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_WITNESS_up_ref(BP_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return 0;

    if (CRYPTO_UP_REF(&witness->references, &ref, witness->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BP_WITNESS", witness);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

/** Decreases the internal reference count of a BP_WITNESS object.
 *  \param  witness  BP_WITNESS object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_WITNESS_down_ref(BP_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return 0;

    if (CRYPTO_DOWN_REF(&witness->references, &ref, witness->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BP_WITNESS", witness);
    REF_ASSERT_ISNT(ref < 0);
    return ((ref > 0) ? 1 : 0);
}

/** Commit v to the witness and calculate V=G^r*H^v
 *  \param  witness   BP_WITNESS object
 *  \param  name      the name used to index the BP_VARIABLE object
 *  \param  v         plaintext BIGNUM object
 *  \return 1 on success and 0 otherwise
 */
int BP_WITNESS_commit(BP_WITNESS *witness, const char *name, const BIGNUM *v)
{
    const BIGNUM *order;
    BIGNUM *r = NULL, *val = NULL;
    EC_POINT *V = NULL;
    BP_VARIABLE *var = NULL;

    if (witness == NULL || v == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (name != NULL && strlen(name) > BP_VARIABLE_NAME_MAX_LEN) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_VARIABLE_NAME_TOO_LONG);
        return 0;
    }

    if (name != NULL && BP_WITNESS_get_variable_index(witness, name) >= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_VARIABLE_DUPLICATED);
        return 0;
    }

    order = EC_GROUP_get0_order(witness->group);

    r = BN_new();
    val = BN_dup(v);
    V = EC_POINT_new(witness->group);
    if (r == NULL || val == NULL || V == NULL)
        goto err;

    if (!zkp_rand_range(r, order))
        goto err;

    /* (69) */
    if (!EC_POINT_mul(witness->group, V, r, witness->H, v, NULL))
        goto err;

    if (!(var = BP_VARIABLE_new(name, V, witness->group)))
        goto err;

    if (sk_BIGNUM_push(witness->sk_r, r) <= 0)
        goto err;

    r = NULL;

    if (sk_BIGNUM_push(witness->sk_v, val) <= 0)
        goto err;

    val = NULL;

    if (sk_BP_VARIABLE_push(witness->sk_V, var) <= 0)
        goto err;

    EC_POINT_free(V);
    return 1;
err:
    BN_free(r);
    BN_free(val);
    EC_POINT_free(V);
    BP_VARIABLE_free(var);
    return 0;
}

/** Get the BP_VARIABLE with the variable name from the witness.
 *  \param  witness   BP_WITNESS object
 *  \param  name      the name of the BP_VARIABLE object
 *  \return the BP_VARIABLE object when found by name, otherwise return NULL.
 */
BP_VARIABLE *BP_WITNESS_get_variable(BP_WITNESS *witness, const char *name)
{
    int i;

    if (witness == NULL || name == NULL) {
        return NULL;
    }

    i = BP_WITNESS_get_variable_index(witness, name);
    if (i < 0) {
        return NULL;
    }

    return sk_BP_VARIABLE_value(witness->sk_V, i);
}

/** Get the index of the BP_VARIABLE in the stack that corresponds to the variable
 *  name from the witness.
 *  \param  witness   BP_WITNESS object
 *  \param  name      the name of the BP_VARIABLE object
 *  \return the index of the BP_VARIABLE object when found by name,
 *  otherwise return -1.
 */
int BP_WITNESS_get_variable_index(BP_WITNESS *witness, const char *name)
{
    int i, num;
    BP_VARIABLE *V;

    if (witness == NULL || name == NULL) {
        return -1;
    }

    num = sk_BP_VARIABLE_num(witness->sk_V);
    for (i = 0; i < num; i++) {
        V = sk_BP_VARIABLE_value(witness->sk_V, i);
        if (V == NULL || V->name == NULL)
            return -1;

        if (OPENSSL_strcasecmp(V->name, name) == 0)
            return i;
    }

    return -1;
}
