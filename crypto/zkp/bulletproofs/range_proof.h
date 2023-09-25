/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BULLET_PROOF_LOCAL_H
# define HEADER_BULLET_PROOF_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/zkp_transcript.h>
# include <openssl/bulletproofs.h>
# include "internal/refcount.h"
# include "bulletproofs.h"
# include "inner_product.h"

struct bp_range_ctx_st {
    ZKP_TRANSCRIPT *transcript;
    BP_PUB_PARAM *pp;
    BP_WITNESS *witness;
};

struct bp_range_proof_st {
    EC_POINT *A;
    EC_POINT *S;
    EC_POINT *T1;
    EC_POINT *T2;
    BIGNUM *taux;
    BIGNUM *mu;
    BIGNUM *tx;
    bp_inner_product_proof_t *ip_proof;
    CRYPTO_RWLOCK *lock;
    CRYPTO_REF_COUNT references;
};

BP_RANGE_PROOF *bp_range_proof_alloc(const EC_GROUP *group);

# ifdef  __cplusplus
}
# endif

#endif

