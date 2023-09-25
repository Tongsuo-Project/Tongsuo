/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BULLETPROOFS_LOCAL_H
# define HEADER_BULLETPROOFS_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/bulletproofs.h>
# include "internal/refcount.h"

# define BP_VARIABLE_NAME_MAX_LEN   16

STACK_OF(BIGNUM);
STACK_OF(EC_POINT);
STACK_OF(BP_VARIABLE);

struct bp_pub_param_st {
    EC_GROUP *group;
    /* `gens_capacity` is the number of generators to precompute for each party.
     *  For range_proof, it is the maximum bitsize of the range_proof,
     *  maximum value is 64.  For r1cs_proof, the capacity must be greater
     *  than the number of multipliers, rounded up to the next power of two.
	 */
    int gens_capacity;
    /* `party_capacity` is the maximum number of parties that can produce an
     *  aggregated range proof. For r1cs_proof, set to 1.
	 */
    int party_capacity;
    STACK_OF(EC_POINT) *sk_G;
    STACK_OF(EC_POINT) *sk_H;
    EC_POINT *H;
    EC_POINT *U;
    CRYPTO_RWLOCK *lock;
    CRYPTO_REF_COUNT references;
};

struct bp_variable_st {
    EC_POINT *point;
    char *name;
};

struct bp_witness_st {
    EC_GROUP *group;
    EC_POINT *H;
    STACK_OF(BIGNUM) *sk_r;
    STACK_OF(BIGNUM) *sk_v;
    STACK_OF(BP_VARIABLE) *sk_V;
    CRYPTO_RWLOCK *lock;
    CRYPTO_REF_COUNT references;
};

# ifdef  __cplusplus
}
# endif

#endif

