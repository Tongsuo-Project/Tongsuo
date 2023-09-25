/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BP_INNER_PRODUCT_LOCAL_H
# define HEADER_BP_INNER_PRODUCT_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include "internal/refcount.h"

typedef struct bp_inner_product_pub_param_st {
    const EC_GROUP *group;
    STACK_OF(EC_POINT) *sk_G;
    STACK_OF(EC_POINT) *sk_H;
} bp_inner_product_pub_param_t;

typedef struct bp_inner_product_ctx_st {
    ZKP_TRANSCRIPT *transcript;
    EC_POINT *P;
    EC_POINT *U;
    STACK_OF(BIGNUM) *sk_G_factors;
    STACK_OF(BIGNUM) *sk_H_factors;
    bp_inner_product_pub_param_t *pp;
} bp_inner_product_ctx_t;

typedef struct bp_inner_product_witness_st {
    STACK_OF(BIGNUM) *sk_a;
    STACK_OF(BIGNUM) *sk_b;
} bp_inner_product_witness_t;

typedef struct bp_inner_product_proof_st {
    STACK_OF(EC_POINT) *sk_L;
    STACK_OF(EC_POINT) *sk_R;
    BIGNUM *a;
    BIGNUM *b;
} bp_inner_product_proof_t;

bp_inner_product_pub_param_t *bp_inner_product_pub_param_new(const EC_GROUP *group,
                                                             STACK_OF(EC_POINT) *sk_G,
                                                             STACK_OF(EC_POINT) *sk_H);
void bp_inner_product_pub_param_free(bp_inner_product_pub_param_t *pp);
bp_inner_product_ctx_t *bp_inner_product_ctx_new(bp_inner_product_pub_param_t *pp,
                                                 ZKP_TRANSCRIPT *transcript,
                                                 EC_POINT *U, EC_POINT *P,
                                                 STACK_OF(BIGNUM) *sk_G_factors,
                                                 STACK_OF(BIGNUM) *sk_H_factors);
void bp_inner_product_ctx_free(bp_inner_product_ctx_t *ctx);
bp_inner_product_witness_t *bp_inner_product_witness_new(STACK_OF(BIGNUM) *sk_a,
                                                         STACK_OF(BIGNUM) *sk_b);
void bp_inner_product_witness_free(bp_inner_product_witness_t *witness);
bp_inner_product_proof_t *bp_inner_product_proof_alloc(int n);
bp_inner_product_proof_t *bp_inner_product_proof_new(bp_inner_product_ctx_t *ctx);
void bp_inner_product_proof_free(bp_inner_product_proof_t *proof);
bp_inner_product_proof_t *bp_inner_product_proof_prove(bp_inner_product_ctx_t *ctx,
                                                       bp_inner_product_witness_t *witness);
int bp_inner_product_proof_verify(bp_inner_product_ctx_t *ctx,
                                  bp_inner_product_proof_t *proof);

# ifdef  __cplusplus
}
# endif

#endif

