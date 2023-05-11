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
#include "bulletproofs.h"
#include "util.h"

/** Creates a new BP_PUB_PARAM object
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
BP_PUB_PARAM *BP_PUB_PARAM_new(int curve_id, int gens_capacity, int party_capacity)
{
    int i, n;
    size_t plen;
    unsigned char *pstr = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL;
    const EC_POINT *G = NULL;
    BP_PUB_PARAM *pp = NULL;
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;

    if (curve_id == NID_undef || gens_capacity <= 0 || party_capacity <= 0) {
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

    pp->curve_id = curve_id;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    pp->group = group;
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

    if (!bp_str2point(group, pstr, plen, pp->H, bn_ctx))
        goto err;

    if (!(pp->U = bp_random_ec_point_new(group, bn_ctx)))
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
        P = bp_random_ec_point_new(group, bn_ctx);
        if (P == NULL)
            goto err;

        if (sk_EC_POINT_push(pp->sk_G, P) <= 0)
            goto err;

        P = bp_random_ec_point_new(group, bn_ctx);
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
 *  \param  curve_name    the elliptic curve name
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

    return BP_PUB_PARAM_new(curve_id, gens_capacity, party_capacity);
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

    if (CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BP_PUB_PARAM", pp);
    REF_ASSERT_ISNT(ref > 0);
    return ((ref > 0) ? 1 : 0);
}
