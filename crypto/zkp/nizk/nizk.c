/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/zkpnizkerr.h>
#include <crypto/ec.h>
#include <crypto/ec/ec_local.h>
#include <crypto/zkp/common/zkp_util.h>
#include "nizk.h"

NIZK_PUB_PARAM *NIZK_PUB_PARAM_new(const EC_GROUP *group, const EC_POINT *G,
                                   const EC_POINT *H)
{
    NIZK_PUB_PARAM *pp = NULL;

    if (group == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    pp = OPENSSL_zalloc(sizeof(*pp));
    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    pp->group = EC_GROUP_dup(group);
    pp->G = EC_POINT_dup(G ? G : EC_GROUP_get0_generator(group), group);

    if (H != NULL) {
        pp->H = EC_POINT_dup(H, group);
    } else {
        pp->H = EC_POINT_new(group);
    }

    if (pp->group == NULL || pp->G == NULL || pp->H == NULL)
        goto err;

    if (H == NULL) {
        if (!zkp_point2point(group, pp->G, pp->H, NULL))
            goto err;
    }

    pp->references = 1;
    if ((pp->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    return pp;
err:
    NIZK_PUB_PARAM_free(pp);
    return NULL;
}

void NIZK_PUB_PARAM_free(NIZK_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return;

    CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock);
    REF_PRINT_COUNT("NIZK_PUB_PARAM", pp);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    EC_POINT_free(pp->G);
    EC_POINT_free(pp->H);
    EC_GROUP_free(pp->group);
    CRYPTO_THREAD_lock_free(pp->lock);
    OPENSSL_clear_free((void *)pp, sizeof(*pp));
}

/** Increases the internal reference count of a NIZK_PUB_PARAM object.
 *  \param  pp  NIZK_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int NIZK_PUB_PARAM_up_ref(NIZK_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return 0;

    if (CRYPTO_UP_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("NIZK_PUB_PARAM", pp);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

/** Decreases the internal reference count of a NIZK_PUB_PARAM object.
 *  \param  pp  NIZK_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int NIZK_PUB_PARAM_down_ref(NIZK_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return 0;

    if (CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("NIZK_PUB_PARAM", pp);
    REF_ASSERT_ISNT(ref < 0);
    return ((ref > 0) ? 1 : 0);
}

/** Creates a new NIZK_WITNESS object
 *  \param  pp           underlying NIZK_PUB_PARAM object
 *  \return newly created NIZK_WITNESS object or NULL in case of an error
 */
NIZK_WITNESS *NIZK_WITNESS_new(const NIZK_PUB_PARAM *pp, const BIGNUM *r,
                               const BIGNUM *v)
{
    NIZK_WITNESS *witness = NULL;

    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(witness->order = BN_dup(EC_GROUP_get0_order(pp->group)))
        || !(witness->r = BN_new())
        || !(witness->v = BN_new())) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (r != NULL) {
        if (!BN_copy(witness->r, r))
            goto err;
    } else {
        zkp_rand_range(witness->r, witness->order);
    }

    if (v != NULL && !BN_copy(witness->v, v))
        goto err;

    witness->references = 1;
    if ((witness->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return witness;
err:
    NIZK_WITNESS_free(witness);
    return NULL;
}

/** Frees a NIZK_WITNESS object
 *  \param  witness   NIZK_WITNESS object to be freed
 */
void NIZK_WITNESS_free(NIZK_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return;

    CRYPTO_DOWN_REF(&witness->references, &ref, witness->lock);
    REF_PRINT_COUNT("NIZK_WITNESS", witness);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    BN_free(witness->order);
    BN_free(witness->r);
    BN_free(witness->v);
    CRYPTO_THREAD_lock_free(witness->lock);
    OPENSSL_free(witness);
}

/** Increases the internal reference count of a NIZK_WITNESS object.
 *  \param  witness  NIZK_WITNESS object
 *  \return 1 on success and 0 if an error occurred.
 */
int NIZK_WITNESS_up_ref(NIZK_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return 0;

    if (CRYPTO_UP_REF(&witness->references, &ref, witness->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("NIZK_WITNESS", witness);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

/** Decreases the internal reference count of a NIZK_WITNESS object.
 *  \param  witness  NIZK_WITNESS object
 *  \return 1 on success and 0 if an error occurred.
 */
int NIZK_WITNESS_down_ref(NIZK_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return 0;

    if (CRYPTO_DOWN_REF(&witness->references, &ref, witness->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("NIZK_WITNESS", witness);
    REF_ASSERT_ISNT(ref < 0);
    return ((ref > 0) ? 1 : 0);
}
