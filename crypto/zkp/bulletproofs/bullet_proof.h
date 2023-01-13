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
# include <openssl/bulletproofs.h>
# include "internal/refcount.h"
# include "inner_product.h"

struct bullet_proof_pub_param_st {
    size_t bits;
    size_t max_agg_num;
    /* size equal bits * max_agg_num */
    EC_POINT **vec_G;
    EC_POINT **vec_H;
    EC_POINT *H;
    EC_POINT *U;
    int curve_id;
};

struct bullet_proof_ctx_st {
    char *st;
    size_t st_len;
    const EC_POINT *G;
    EC_GROUP *group;
    BULLET_PROOF_PUB_PARAM *pp;
};

struct bullet_proof_witness_st {
    size_t n;
    BIGNUM **vec_r;
    BIGNUM **vec_v;
};

struct bullet_proof_st {
    size_t n;
    EC_POINT **V;
    EC_POINT *A;
    EC_POINT *S;
    EC_POINT *T1;
    EC_POINT *T2;
    BIGNUM *taux;
    BIGNUM *mu;
    BIGNUM *tx;
    bp_inner_product_proof_t *ip_proof;
};

# ifdef  __cplusplus
}
# endif

#endif

